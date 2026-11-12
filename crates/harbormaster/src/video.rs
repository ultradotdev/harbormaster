//! Live camera streams for HomeKit.
//!
//! When a controller asks for a stream, an ffmpeg process is started that
//! reads the camera's video, re-encodes it with the GPU (VideoToolbox) to
//! the size and bitrate the controller chose, and sends it straight to the
//! controller as encrypted RTP. One process per viewer, stopped when the
//! controller says so or disconnects.

use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use harbormaster_hap::camera::{
    self, kind, parse_selected, parse_setup, Command, SelectedAudio, SelectedVideo, SetupRequest, SetupResponse,
};
use harbormaster_hap::model::status;
use harbormaster_hap::{Accessory, Database};
use serde_json::Value;
use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

/// Where a camera's video comes from.
pub trait VideoSource: Send + Sync {
    /// Whether the camera can be reached right now.
    fn available(&self) -> bool;

    /// Starts reading a stream about `width` pixels wide, or returns `None`
    /// if the camera cannot be reached. What arrives is fragmented MP4, the
    /// header first; the source stops reading when the receiver is dropped.
    /// Must be called from within the async runtime.
    fn open(&self, width: u16) -> Option<mpsc::Receiver<Bytes>>;
}

/// How ffmpeg is told to read the stream handed to it on standard input.
fn input_args() -> Vec<String> {
    [
        // Whatever ffmpeg reads while working out what the stream is gets
        // sent in a burst afterwards, and the viewer then stays that far
        // behind for the whole session. So probe as little as possible.
        "-flags",
        "low_delay",
        "-fpsprobesize",
        "0",
        "-analyzeduration",
        "200000",
        "-probesize",
        "200000",
        // Decoding stays in software: the hardware decoder rejected the
        // first frames of nearly every stream, and those include the
        // keyframe everything after depends on. Encoding, the expensive
        // half, still runs on the GPU.
        "-f",
        "mp4",
        "-i",
        "pipe:0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Finds ffmpeg. A service started by launchd has a minimal `PATH`, so the
/// usual install locations are checked explicitly.
pub fn find_ffmpeg() -> Option<PathBuf> {
    ["/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/usr/bin/ffmpeg"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// Resolutions offered to HomeKit for a camera whose best stream has the
/// given size, keeping the camera's aspect ratio so nothing is stretched.
pub fn resolutions(max_width: u16, max_height: u16) -> Vec<(u16, u16, u8)> {
    // Width to height closer to 4:3 than to 16:9.
    let four_by_three = (max_width as u32) * 9 < (max_height as u32) * 14;
    let ladder: &[(u16, u16)] = if four_by_three {
        &[(1600, 1200), (1440, 1080), (1280, 960), (1024, 768), (640, 480), (480, 360), (320, 240)]
    } else {
        &[(1920, 1080), (1280, 720), (1024, 576), (640, 360), (480, 270), (320, 180)]
    };
    let mut out: Vec<(u16, u16, u8)> =
        ladder.iter().filter(|(w, _)| *w <= max_width.max(320)).map(|(w, h)| (*w, *h, 30)).collect();
    // Apple Watch asks for a small, slow stream.
    let (w, h) = *ladder.last().expect("ladders are not empty");
    out.push((w, h, 15));
    out
}

/// Says why a camera may not be watched right now, or `None` if it may.
pub type Gate = Arc<dyn Fn() -> Option<&'static str> + Send + Sync>;

/// Instance ids of one stream management service.
#[derive(Clone, Copy, Debug)]
pub struct StreamIds {
    selected: u64,
    setup: u64,
    status: u64,
    active: u64,
}

/// Adds a stream management service at a fixed instance id.
pub fn add_stream_service(accessory: &mut Accessory, iid: u64, offered: &[(u16, u16, u8)]) -> StreamIds {
    let ids = accessory.add_service_at(
        iid,
        kind::CAMERA_RTP_STREAM_MANAGEMENT,
        false,
        camera::stream_characteristics(offered),
    );
    StreamIds { selected: ids[0], setup: ids[1], status: ids[2], active: ids[6] }
}

impl StreamIds {
    /// The characteristic HomeKit uses to switch this stream on and off.
    pub fn active(&self) -> u64 {
        self.active
    }
}

/// A stream the controller has set up but not yet started.
struct Pending {
    request: SetupRequest,
    ssrc: u32,
    audio_ssrc: u32,
    connection: u64,
    /// Held so the port reported to the controller stays reserved.
    socket: UdpSocket,
}

struct Running {
    session_id: [u8; 16],
    connection: u64,
    /// Dropping this stops the ffmpeg process.
    _stop: oneshot::Sender<()>,
}

#[derive(Default)]
struct State {
    pending: Option<Pending>,
    running: Option<Running>,
}

struct Stream {
    name: String,
    aid: u64,
    ids: StreamIds,
    db: Arc<Database>,
    source: Arc<dyn VideoSource>,
    ffmpeg: PathBuf,
    gate: Option<Gate>,
    state: Mutex<State>,
}

/// Connects a stream management service to a video source. Must be called
/// from within the async runtime, after the accessory is in the database.
pub fn install(
    db: &Arc<Database>,
    aid: u64,
    ids: StreamIds,
    name: &str,
    source: Arc<dyn VideoSource>,
    ffmpeg: &Path,
    gate: Option<Gate>,
) {
    let stream = Arc::new(Stream {
        name: name.to_owned(),
        aid,
        ids,
        db: db.clone(),
        source,
        ffmpeg: ffmpeg.to_owned(),
        gate,
        state: Mutex::new(State::default()),
    });
    let s = stream.clone();
    db.on_write(aid, ids.setup, Arc::new(move |value, ctx| s.setup(value, ctx.connection, ctx.local_ip)));
    let s = stream.clone();
    db.on_write(aid, ids.selected, Arc::new(move |value, _| s.selected(value)));

    // A controller that vanishes never sends "end", so watch for its
    // connection closing. The task ends once the stream itself is dropped.
    let mut closed = db.subscribe_connection_closed();
    let weak = Arc::downgrade(&stream);
    tokio::spawn(async move {
        // Also look every couple of seconds for the camera having been
        // switched off in HomeKit while someone is watching.
        let mut check = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tokio::select! {
                closed = closed.recv() => {
                    let connection = match closed {
                        Ok(connection) => connection,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => return,
                    };
                    let Some(stream) = weak.upgrade() else { return };
                    stream.connection_closed(connection);
                }
                _ = check.tick() => {
                    let Some(stream) = weak.upgrade() else { return };
                    if let Some(why) = stream.refusal() {
                        let watching = stream.state.lock().unwrap().running.is_some();
                        if watching {
                            tracing::info!("{}: ending live view: {why}", stream.name);
                            stream.stop_if(|_| true);
                        }
                    }
                }
            }
        }
    });
}

impl Stream {
    /// Why HomeKit's own switches forbid watching right now, if they do.
    fn refusal(&self) -> Option<&'static str> {
        self.gate.as_ref().and_then(|gate| gate())
    }

    fn set_status(&self, status: u8) {
        self.db.set(self.aid, self.ids.status, camera::streaming_status(status));
    }

    fn setup(&self, value: &Value, connection: u64, local_ip: IpAddr) -> Result<Option<Value>, i32> {
        let request = parse_setup(value).ok_or(status::INVALID_VALUE)?;
        let unavailable = |why: &str| {
            tracing::warn!("{}: cannot start a stream: {why}", self.name);
            Ok(Some(camera::setup_error(&request.session_id)))
        };
        if request.video_srtp.suite != camera::SRTP_AES_CM_128_HMAC_SHA1_80 {
            return unavailable("the controller asked for an encryption suite that was not offered");
        }
        if self.db.read(self.aid, self.ids.active) == Ok(serde_json::json!(0)) {
            return unavailable("streaming is switched off for this camera in HomeKit");
        }
        if let Some(why) = self.refusal() {
            return unavailable(why);
        }
        if !self.source.available() {
            return unavailable("the camera is not reachable");
        }
        // Reserve a local port for the controller's control traffic.
        let bind = if local_ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let Ok(socket) = UdpSocket::bind(bind) else { return unavailable("no free UDP port") };
        let Ok(port) = socket.local_addr().map(|a| a.port()) else { return unavailable("no free UDP port") };
        // ffmpeg takes the stream identifier as a signed number, so keep it
        // positive, and never zero.
        let ssrc = (u32::from_le_bytes(random_bytes()) & 0x7fff_ffff).max(1);
        let audio_ssrc = (ssrc ^ 0x0100_0000).max(1);
        let response = SetupResponse {
            request: &request,
            local_ip,
            video_port: port,
            // Nothing the controller sends back is used, so one port takes
            // the control traffic for both video and audio.
            audio_port: port,
            video_ssrc: ssrc,
            audio_ssrc,
        }
        .encode();
        self.state.lock().unwrap().pending = Some(Pending { request, ssrc, audio_ssrc, connection, socket });
        Ok(Some(response))
    }

    fn selected(self: &Arc<Self>, value: &Value) -> Result<Option<Value>, i32> {
        let selected = parse_selected(value).ok_or(status::INVALID_VALUE)?;
        match selected.command {
            Command::Start => {
                let video = selected.video.ok_or(status::INVALID_VALUE)?;
                let selected_audio = selected.audio.clone();
                let pending = {
                    let mut state = self.state.lock().unwrap();
                    match state.pending.take() {
                        Some(p) if p.request.session_id == selected.session_id => p,
                        other => {
                            state.pending = other;
                            return Err(status::INVALID_VALUE);
                        }
                    }
                };
                // Sound is left out rather than refusing the stream if the
                // controller picked something that was not offered.
                let audio = selected.audio.filter(|a| {
                    matches!(a.codec, camera::AAC_ELD | camera::OPUS)
                        && pending.request.audio_srtp.suite == camera::SRTP_AES_CM_128_HMAC_SHA1_80
                });
                if audio.is_none() {
                    match &selected_audio {
                        Some(a) => tracing::info!(
                            "{}: no sound: the controller chose audio codec {} at {} Hz, which was not offered",
                            self.name,
                            a.codec,
                            a.sample_rate_hz
                        ),
                        None => tracing::info!("{}: no sound: the controller sent no usable audio settings", self.name),
                    }
                }
                self.start(pending, video, audio);
            }
            Command::End => self.stop_if(|running| running.session_id == selected.session_id),
            // Pausing and bitrate changes are accepted but not acted on.
            Command::Suspend | Command::Resume | Command::Reconfigure => {}
        }
        Ok(None)
    }

    fn connection_closed(&self, connection: u64) {
        self.stop_if(|running| running.connection == connection);
        let mut state = self.state.lock().unwrap();
        if state.pending.as_ref().is_some_and(|p| p.connection == connection) {
            state.pending = None;
        }
    }

    fn stop_if(&self, matches: impl Fn(&Running) -> bool) {
        let mut state = self.state.lock().unwrap();
        if state.running.as_ref().is_some_and(matches) {
            // Dropping the sender signals the process task to kill ffmpeg.
            state.running = None;
        }
    }

    fn start(self: &Arc<Self>, pending: Pending, video: SelectedVideo, audio: Option<SelectedAudio>) {
        let Some(mut feed) = self.source.open(video.width) else {
            tracing::warn!("{}: the camera became unreachable before the stream started", self.name);
            return;
        };
        let args =
            ffmpeg_args(&input_args(), &pending.request, &video, pending.ssrc, audio.as_ref().map(|a| (a, pending.audio_ssrc)));
        let mut command = tokio::process::Command::new(&self.ffmpeg);
        command.args(&args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                tracing::error!("{}: could not start {}: {e}", self.name, self.ffmpeg.display());
                return;
            }
        };
        tracing::info!(
            "{}: streaming {}x{} at {} fps, {} kbps, {} to {}",
            self.name,
            video.width,
            video.height,
            video.fps,
            video.max_bitrate_kbps,
            match &audio {
                Some(a) => format!(
                    "{} sound at {} kHz, {} kbps",
                    if a.codec == camera::OPUS { "Opus" } else { "AAC" },
                    a.sample_rate_hz / 1000,
                    a.max_bitrate_kbps
                ),
                None => "no sound".to_owned(),
            },
            pending.request.controller_ip
        );

        let (stop, mut stopped) = oneshot::channel::<()>();
        let session_id = pending.request.session_id;
        {
            let mut state = self.state.lock().unwrap();
            // Replacing a previous stream drops its sender, which stops it.
            state.running = Some(Running { session_id, connection: pending.connection, _stop: stop });
        }
        self.set_status(camera::STATUS_IN_USE);

        // Hand the camera's video to ffmpeg as it arrives. Closing ffmpeg's
        // input when the feed ends lets it finish cleanly.
        let stdin = child.stdin.take();
        let progress = Arc::new(Progress::default());
        let counting = progress.clone();
        let writer = tokio::spawn(async move {
            let Some(mut stdin) = stdin else { return };
            while let Some(data) = feed.recv().await {
                counting.received.fetch_add(data.len() as u64, Ordering::Relaxed);
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
            }
        });

        let stream = self.clone();
        let stderr = child.stderr.take();
        let viewer = pending.request.controller_ip;
        let began = std::time::Instant::now();
        tokio::spawn(async move {
            // Keep the reserved port for as long as the stream lives.
            let _socket = pending.socket;
            let _viewing = crate::status::global().viewing(stream.aid, viewer, video.width, video.height);
            if let Some(stderr) = stderr {
                let name = stream.name.clone();
                let progress = progress.clone();
                tokio::spawn(async move {
                    // ffmpeg repeats a complaint for every frame it cannot
                    // use, so each distinct one is logged once and counted.
                    let mut seen = Repeats::default();
                    let mut lines = BufReader::new(stderr).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if progress.note(&line) {
                            continue;
                        }
                        if seen.first(&line) {
                            tracing::warn!("{name}: ffmpeg: {line}");
                        }
                    }
                    for (line, extra) in seen.repeated() {
                        tracing::warn!("{name}: ffmpeg: {line} ({extra} more like this)");
                    }
                });
            }
            tokio::select! {
                exit = child.wait() => match exit {
                    Ok(code) if code.success() => tracing::info!("{}: stream to {viewer} ended", stream.name),
                    Ok(code) => tracing::warn!("{}: ffmpeg stopped unexpectedly ({code})", stream.name),
                    Err(e) => tracing::warn!("{}: lost track of ffmpeg: {e}", stream.name),
                },
                // Fires when the sender is dropped, however the stream was ended.
                _ = &mut stopped => {
                    let _ = child.kill().await;
                }
            }
            // Whether video actually flowed, which the lines above cannot say.
            tracing::info!(
                "{}: stream to {viewer} stopped after {:.0} s: the camera supplied {} kB; ffmpeg sent {} frames, {} kB",
                stream.name,
                began.elapsed().as_secs_f64(),
                progress.received.load(Ordering::Relaxed) / 1000,
                progress.frames.load(Ordering::Relaxed),
                progress.sent.load(Ordering::Relaxed) / 1000
            );
            // Dropping the feed is what tells the source to stop reading.
            writer.abort();
            let mut state = stream.state.lock().unwrap();
            if state.running.as_ref().is_some_and(|r| r.session_id == session_id) {
                state.running = None;
            }
            if state.running.is_none() {
                drop(state);
                stream.set_status(camera::STATUS_AVAILABLE);
            }
        });
    }
}

/// How much video went into and came out of one ffmpeg.
#[derive(Default)]
struct Progress {
    /// Bytes of camera video handed to ffmpeg.
    received: AtomicU64,
    /// Video frames ffmpeg reports having sent.
    frames: AtomicU64,
    /// Bytes ffmpeg reports having sent.
    sent: AtomicU64,
}

impl Progress {
    /// Takes a line of ffmpeg's output and says whether it was one of its
    /// periodic `key=value` progress reports rather than a complaint.
    fn note(&self, line: &str) -> bool {
        let Some((key, value)) = line.split_once('=') else { return false };
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return false;
        }
        let target = match key {
            "frame" => &self.frames,
            "total_size" => &self.sent,
            _ => return true,
        };
        if let Ok(n) = value.trim().parse() {
            target.store(n, Ordering::Relaxed);
        }
        true
    }
}

fn random_bytes() -> [u8; 4] {
    // Std's hasher seeds are random per process and per instance, which is
    // plenty for a stream identifier that only needs to be unpredictable
    // enough not to collide.
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
    (hasher.finish() as u32).to_le_bytes()
}

/// The ffmpeg command line for one stream. `input` says how to read the
/// camera; everything after it is determined by what the controller asked.
fn ffmpeg_args(
    input: &[String],
    request: &SetupRequest,
    video: &SelectedVideo,
    ssrc: u32,
    audio: Option<(&SelectedAudio, u32)>,
) -> Vec<String> {
    let profile = match video.profile {
        0 => "baseline",
        1 => "main",
        _ => "high",
    };
    let level = match video.level {
        0 => "3.1",
        1 => "3.2",
        _ => "4.0",
    };
    let fps = video.fps.max(1);
    let bitrate = format!("{}k", video.max_bitrate_kbps.max(32));
    // Stay under common MTUs once SRTP's authentication tag is added.
    let packet = video.mtu.unwrap_or(1378).clamp(576, 1378);
    let host = match request.controller_ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let port = request.video_port;
    let fixed = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // Progress is reported on the error stream every two seconds, where it
    // is counted instead of logged.
    let mut args = fixed(&["-hide_banner", "-loglevel", "error", "-nostdin", "-progress", "pipe:2", "-stats_period", "2"]);
    args.extend_from_slice(input);
    args.extend(fixed(&["-map", "0:v:0", "-an", "-sn", "-dn"]));
    args.extend([
        "-vf".into(),
        format!("scale={}:{}", video.width, video.height),
        "-r".into(),
        fps.to_string(),
        "-codec:v".into(),
        "h264_videotoolbox".into(),
        // Favour latency over compression, and fall back to software
        // encoding rather than failing if the hardware encoder is busy.
        "-realtime".into(),
        "1".into(),
        "-allow_sw".into(),
        "1".into(),
        "-profile:v".into(),
        profile.into(),
        "-level:v".into(),
        level.into(),
        "-b:v".into(),
        bitrate.clone(),
        "-maxrate".into(),
        bitrate,
        // B-frames would make the encoder hold frames back to reorder them.
        "-bf".into(),
        "0".into(),
        // A keyframe every two seconds lets a viewer recover from loss.
        "-g".into(),
        (fps as u32 * 2).to_string(),
        "-payload_type".into(),
        video.payload_type.to_string(),
        "-ssrc".into(),
        ssrc.to_string(),
        "-f".into(),
        "rtp".into(),
        "-srtp_out_suite".into(),
        "AES_CM_128_HMAC_SHA1_80".into(),
        "-srtp_out_params".into(),
        request.video_srtp.key_material(),
        format!("srtp://{host}:{port}?rtcpport={port}&pkt_size={packet}"),
    ]);
    if let Some((audio, ssrc)) = audio {
        let port = request.audio_port;
        // A second output of the same process, so sound and picture share
        // one connection to the camera and stay in step. The `?` lets a
        // camera without a microphone still stream video.
        args.extend(fixed(&["-map", "0:a:0?", "-vn", "-sn", "-dn"]));
        if audio.codec == camera::OPUS {
            // Opus frames come in 20, 40 or 60 ms; use what was asked for
            // when it is one of those.
            let frame = if matches!(audio.packet_time_ms, 40 | 60) { audio.packet_time_ms } else { 20 };
            args.extend(fixed(&["-codec:a", "libopus", "-application", "lowdelay", "-frame_duration"]));
            args.push(frame.to_string());
        } else {
            // Apple's own encoder. Profile 38 is AAC-ELD, which this
            // encoder does not accept by name. The global header is
            // required for this format to be packed into RTP.
            let encoder = ["-codec:a", "aac_at", "-profile:a", "38", "-aac_at_mode", "cvbr", "-flags", "+global_header"];
            args.extend(fixed(&encoder));
        }
        args.extend([
            "-ar".into(),
            audio.sample_rate_hz.to_string(),
            "-ac".into(),
            "1".into(),
            "-b:a".into(),
            format!("{}k", audio.max_bitrate_kbps.clamp(8, 64)),
            "-payload_type".into(),
            audio.payload_type.to_string(),
            "-ssrc".into(),
            ssrc.to_string(),
            "-f".into(),
            "rtp".into(),
            "-srtp_out_suite".into(),
            "AES_CM_128_HMAC_SHA1_80".into(),
            "-srtp_out_params".into(),
            request.audio_srtp.key_material(),
            // Small packets so each carries one frame of sound and none
            // waits for the next.
            format!("srtp://{host}:{port}?rtcpport={port}&pkt_size=188"),
        ]);
    }
    args
}

/// Counts repeated ffmpeg messages so a burst of identical complaints takes
/// one log line and a total rather than one line per video frame.
#[derive(Default)]
pub(crate) struct Repeats {
    /// Message with addresses removed, first full line, and times seen.
    seen: Vec<(String, String, u32)>,
}

impl Repeats {
    /// Distinct messages remembered per stream; anything past this is logged
    /// as it comes so the memory used cannot grow without limit.
    const LIMIT: usize = 32;

    /// Records a line and says whether it should be logged now.
    pub(crate) fn first(&mut self, line: &str) -> bool {
        let key = without_addresses(line);
        if let Some(entry) = self.seen.iter_mut().find(|(k, _, _)| *k == key) {
            entry.2 = entry.2.saturating_add(1);
            return false;
        }
        if self.seen.len() < Self::LIMIT {
            self.seen.push((key, line.to_owned(), 1));
        }
        true
    }

    /// Messages seen more than once, with how many times beyond the first.
    pub(crate) fn repeated(&self) -> impl Iterator<Item = (&str, u32)> {
        self.seen.iter().filter(|(_, _, n)| *n > 1).map(|(_, line, n)| (line.as_str(), n - 1))
    }
}

/// Drops `0x…` pointer values, which differ between otherwise equal lines.
fn without_addresses(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find("0x") {
        out.push_str(&rest[..at]);
        rest = rest[at + 2..].trim_start_matches(|c: char| c.is_ascii_hexdigit());
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use harbormaster_hap::camera::Srtp;
    use harbormaster_hap::model::WriteContext;
    use harbormaster_hap::Info;
    use std::time::Duration;

    fn request(ip: &str, port: u16) -> SetupRequest {
        let srtp = Srtp { suite: 0, key: vec![1; 16], salt: vec![2; 14] };
        SetupRequest {
            session_id: [9; 16],
            controller_ip: ip.parse().unwrap(),
            video_port: port,
            audio_port: port + 2,
            video_srtp: srtp.clone(),
            audio_srtp: srtp,
        }
    }

    fn video(width: u16, height: u16) -> SelectedVideo {
        SelectedVideo { profile: 1, level: 2, width, height, fps: 30, payload_type: 99, max_bitrate_kbps: 299, mtu: Some(1378) }
    }

    #[test]
    fn progress_reports_are_counted_and_complaints_are_not() {
        let progress = Progress::default();
        assert!(progress.note("frame=150"));
        assert!(progress.note("total_size=   204800"));
        assert!(progress.note("out_time_ms=5000000"));
        assert!(progress.note("progress=continue"));
        assert!(progress.note("stream_0_0_q=-0.0"));
        assert!(!progress.note("[h264 @ 0x1] hardware accelerator failed to decode picture"));
        assert!(!progress.note("Error opening output file srtp://x?rtcpport=1&pkt_size=2"));
        assert!(!progress.note("Conversion failed!"));
        assert_eq!(progress.frames.load(Ordering::Relaxed), 150);
        assert_eq!(progress.sent.load(Ordering::Relaxed), 204800);
    }

    #[test]
    fn repeated_ffmpeg_messages_are_logged_once_and_counted() {
        let mut seen = Repeats::default();
        assert!(seen.first("[h264 @ 0x13660a3f0] hardware accelerator failed to decode picture"));
        assert!(!seen.first("[h264 @ 0x7f00aa] hardware accelerator failed to decode picture"));
        assert!(!seen.first("[h264 @ 0x13660a3f0] hardware accelerator failed to decode picture"));
        assert!(seen.first("Connection refused"));
        let repeated: Vec<_> = seen.repeated().collect();
        assert_eq!(repeated, [("[h264 @ 0x13660a3f0] hardware accelerator failed to decode picture", 2)]);

        // Past the limit, new messages are still logged, just not counted.
        for n in 0..Repeats::LIMIT {
            seen.first(&format!("message {n}"));
        }
        assert!(seen.first("one more"));
        assert!(seen.first("one more"));
    }

    #[test]
    fn offers_resolutions_in_the_camera_aspect_ratio() {
        let wide = resolutions(1920, 1080);
        assert_eq!(wide.first(), Some(&(1920, 1080, 30)));
        assert_eq!(wide.last(), Some(&(320, 180, 15)));
        let doorbell = resolutions(1600, 1200);
        assert_eq!(doorbell.first(), Some(&(1600, 1200, 30)));
        assert!(doorbell.iter().all(|(w, h, _)| w * 3 == h * 4));
        // Never offers more than the camera has.
        assert_eq!(resolutions(1280, 720).first(), Some(&(1280, 720, 30)));
    }

    #[test]
    fn ffmpeg_command_carries_the_negotiated_settings() {
        let input = input_args();
        let args = ffmpeg_args(&input, &request("10.0.0.9", 50000), &video(1280, 720), 12345, None);
        let line = args.join(" ");
        assert!(!line.contains("aac_at"), "no sound was selected: {line}");
        for expected in [
            "-probesize 200000 -f mp4 -i pipe:0",
            "-vf scale=1280:720",
            "-r 30",
            "-codec:v h264_videotoolbox",
            "-profile:v main",
            "-level:v 4.0",
            "-b:v 299k",
            "-bf 0",
            "-g 60",
            "-payload_type 99",
            "-ssrc 12345",
            "-srtp_out_suite AES_CM_128_HMAC_SHA1_80",
            "srtp://10.0.0.9:50000?rtcpport=50000&pkt_size=1378",
        ] {
            assert!(line.contains(expected), "missing {expected:?} in {line}");
        }
        let v6 = ffmpeg_args(&input, &request("fe80::1", 50000), &video(320, 240), 1, None);
        assert!(v6.last().unwrap().starts_with("srtp://[fe80::1]:50000?"));
    }

    #[test]
    fn ffmpeg_command_adds_sound_as_a_second_output() {
        let input = vec!["-i".to_owned(), "SOURCE".to_owned()];
        let audio =
            SelectedAudio { codec: camera::AAC_ELD, sample_rate_hz: 16000, payload_type: 110, max_bitrate_kbps: 24, packet_time_ms: 30 };
        let args = ffmpeg_args(&input, &request("10.0.0.9", 50000), &video(1280, 720), 12345, Some((&audio, 777)));
        let line = args.join(" ");
        // Everything after the video destination belongs to the sound.
        let (video_part, audio_part) = line.split_once("pkt_size=1378 ").expect("video output comes first");
        assert!(video_part.contains("-map 0:v:0 -an"), "{video_part}");
        for expected in [
            "-map 0:a:0? -vn",
            "-codec:a aac_at -profile:a 38",
            "-ar 16000 -ac 1 -b:a 24k",
            "-payload_type 110 -ssrc 777",
            "-srtp_out_suite AES_CM_128_HMAC_SHA1_80",
        ] {
            assert!(audio_part.contains(expected), "missing {expected:?} in {audio_part}");
        }
        assert_eq!(args.last().unwrap(), "srtp://10.0.0.9:50002?rtcpport=50002&pkt_size=188");

        let opus = SelectedAudio { codec: camera::OPUS, packet_time_ms: 30, ..audio };
        let line = ffmpeg_args(&input, &request("10.0.0.9", 50000), &video(1280, 720), 12345, Some((&opus, 777))).join(" ");
        assert!(line.contains("-codec:a libopus -application lowdelay -frame_duration 20 -ar 16000"), "{line}");
        assert!(!line.contains("aac_at"), "{line}");
    }

    /// A stand-in camera: a second ffmpeg that produces a test picture and
    /// tone as fragmented MP4 in real time, the shape of a real feed.
    pub(crate) struct TestPattern(pub(crate) PathBuf);

    impl VideoSource for TestPattern {
        fn available(&self) -> bool {
            true
        }

        fn open(&self, _width: u16) -> Option<mpsc::Receiver<Bytes>> {
            use tokio::io::AsyncReadExt;
            let args = [
                "-hide_banner", "-loglevel", "error", "-nostdin", "-re",
                "-f", "lavfi", "-i", "testsrc=size=640x480:rate=30",
                "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
                "-codec:v", "h264_videotoolbox", "-g", "30", "-codec:a", "aac",
                "-movflags", "frag_keyframe+empty_moov+default_base_moof", "-frag_duration", "100000",
                "-f", "mp4", "pipe:1",
            ];
            let mut child = tokio::process::Command::new(&self.0)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .ok()?;
            let mut stdout = child.stdout.take()?;
            let (sender, receiver) = mpsc::channel(32);
            tokio::spawn(async move {
                let _child = child;
                // Hand over the header and then whole fragments, as the
                // real feed does, whatever sizes the pipe delivers.
                let mut splitter = crate::fmp4::Splitter::default();
                let mut chunk = vec![0u8; 16 * 1024];
                while let Ok(n) = stdout.read(&mut chunk).await {
                    let mut pieces = Vec::new();
                    if n == 0 || splitter.feed(&chunk[..n], &mut pieces).is_err() {
                        break;
                    }
                    for piece in pieces {
                        let (crate::fmp4::Piece::Header(data) | crate::fmp4::Piece::Fragment(data)) = piece;
                        if sender.send(Bytes::from(data)).await.is_err() {
                            return;
                        }
                    }
                }
            });
            Some(receiver)
        }
    }

    struct Offline;

    impl VideoSource for Offline {
        fn available(&self) -> bool {
            false
        }

        fn open(&self, _width: u16) -> Option<mpsc::Receiver<Bytes>> {
            None
        }
    }

    fn camera(source: Arc<dyn VideoSource>, ffmpeg: &Path) -> (Arc<Database>, StreamIds) {
        let info = Info { name: "Cam", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
        let mut accessory = Accessory::new(2, &info);
        let ids = add_stream_service(&mut accessory, 200, &resolutions(640, 480));
        let db = Database::new();
        db.add(accessory);
        install(&db, 2, ids, "Cam", source, ffmpeg, None);
        (db, ids)
    }

    fn context(connection: u64) -> WriteContext {
        WriteContext {
            connection,
            local_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.1".parse().unwrap(),
            shared_secret: None,
        }
    }

    /// Builds the two controller writes the way an Apple device would.
    fn controller_writes(port: u16, command: u8) -> (Value, Value) {
        use harbormaster_hap::camera::test_support::{selected_value, setup_value};
        (setup_value("127.0.0.1", port), selected_value(command, 640, 480, 30, 299))
    }

    #[tokio::test]
    async fn offline_camera_answers_with_an_error_status() {
        let (db, ids) = camera(Arc::new(Offline), Path::new("/nonexistent"));
        let (setup, _) = controller_writes(50000, 1);
        db.write(2, ids.setup, &setup, &context(1)).unwrap();
        let answer = db.read(2, ids.setup).unwrap();
        assert_eq!(harbormaster_hap::camera::test_support::setup_status(&answer), Some(2));
    }

    /// Two sockets two ports apart, the way a controller lays out the
    /// video and audio ports it listens on.
    async fn receivers() -> (tokio::net::UdpSocket, tokio::net::UdpSocket) {
        for _ in 0..50 {
            let video = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = video.local_addr().unwrap().port();
            if let Ok(audio) = tokio::net::UdpSocket::bind(("127.0.0.1", port.wrapping_add(2))).await {
                return (video, audio);
            }
        }
        panic!("no pair of free UDP ports");
    }

    /// Reads until something other than a control packet (sender reports,
    /// types 200 to 204, share the port) arrives; returns its payload type.
    async fn media_payload_type(socket: &tokio::net::UdpSocket) -> u8 {
        let mut packet = [0u8; 2048];
        loop {
            let n = socket.recv(&mut packet).await.unwrap();
            assert!(n > 12, "packet too short to be RTP");
            assert_eq!(packet[0] >> 6, 2, "RTP version");
            if !(200..=204).contains(&packet[1]) {
                return packet[1] & 0x7f;
            }
        }
    }

    /// Runs a real ffmpeg with a test pattern and tone and checks encrypted
    /// RTP actually arrives for both. Skipped where ffmpeg is not installed.
    #[tokio::test]
    async fn real_ffmpeg_delivers_rtp_and_stops_on_end_or_disconnect() {
        let Some(ffmpeg) = find_ffmpeg() else {
            eprintln!("ffmpeg not installed; skipping");
            return;
        };
        let (db, ids) = camera(Arc::new(TestPattern(ffmpeg.clone())), &ffmpeg);
        let (receiver, audio_receiver) = receivers().await;
        let port = receiver.local_addr().unwrap().port();
        let (setup, start) = controller_writes(port, 1);

        db.write(2, ids.setup, &setup, &context(7)).unwrap();
        let answer = db.read(2, ids.setup).unwrap();
        assert_eq!(harbormaster_hap::camera::test_support::setup_status(&answer), Some(0));
        db.write(2, ids.selected, &start, &context(7)).unwrap();
        assert_eq!(db.read(2, ids.status).unwrap(), camera::streaming_status(camera::STATUS_IN_USE));

        let mut packet = [0u8; 2048];
        let payload_type = tokio::time::timeout(Duration::from_secs(15), media_payload_type(&receiver))
            .await
            .expect("no video arrived from ffmpeg");
        assert_eq!(payload_type, 99, "the negotiated payload type");
        let payload_type = tokio::time::timeout(Duration::from_secs(15), media_payload_type(&audio_receiver))
            .await
            .expect("no sound arrived from ffmpeg");
        assert_eq!(payload_type, 110, "the negotiated audio payload type");

        // A controller that disconnects without saying "end" stops the stream.
        db.connection_closed(7);
        let available = camera::streaming_status(camera::STATUS_AVAILABLE);
        let mut waited = 0;
        while db.read(2, ids.status).unwrap() != available {
            tokio::time::sleep(Duration::from_millis(100)).await;
            waited += 1;
            assert!(waited < 50, "stream did not stop after the controller disconnected");
        }
        // Drain what was in flight, then confirm nothing more is sent.
        tokio::time::sleep(Duration::from_millis(300)).await;
        while receiver.try_recv(&mut packet).is_ok() {}
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(receiver.try_recv(&mut packet).is_err(), "ffmpeg kept sending after the stream stopped");
    }
}
