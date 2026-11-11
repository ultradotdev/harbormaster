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
use std::sync::{Arc, Mutex};

use harbormaster_hap::camera::{
    self, kind, parse_selected, parse_setup, Command, SelectedVideo, SetupRequest, SetupResponse,
};
use harbormaster_hap::model::status;
use harbormaster_hap::{Accessory, Database};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::oneshot;

/// Where a camera's video comes from.
pub trait VideoSource: Send + Sync {
    /// ffmpeg input arguments for a stream about `width` pixels wide, or
    /// `None` if the camera cannot be reached right now. These may contain
    /// secrets and must not be logged.
    fn input_args(&self, width: u16) -> Option<Vec<String>>;
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

/// Instance ids of one stream management service.
#[derive(Clone, Copy, Debug)]
pub struct StreamIds {
    selected: u64,
    setup: u64,
    status: u64,
}

/// Adds a stream management service at a fixed instance id.
pub fn add_stream_service(accessory: &mut Accessory, iid: u64, offered: &[(u16, u16, u8)]) -> StreamIds {
    let ids = accessory.add_service_at(
        iid,
        kind::CAMERA_RTP_STREAM_MANAGEMENT,
        false,
        camera::stream_characteristics(offered),
    );
    StreamIds { selected: ids[0], setup: ids[1], status: ids[2] }
}

/// A stream the controller has set up but not yet started.
struct Pending {
    request: SetupRequest,
    ssrc: u32,
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
) {
    let stream = Arc::new(Stream {
        name: name.to_owned(),
        aid,
        ids,
        db: db.clone(),
        source,
        ffmpeg: ffmpeg.to_owned(),
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
        loop {
            let connection = match closed.recv().await {
                Ok(connection) => connection,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            let Some(stream) = weak.upgrade() else { return };
            stream.connection_closed(connection);
        }
    });
}

impl Stream {
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
        if self.source.input_args(0).is_none() {
            return unavailable("the camera is not reachable");
        }
        // Reserve a local port for the controller's control traffic.
        let bind = if local_ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let Ok(socket) = UdpSocket::bind(bind) else { return unavailable("no free UDP port") };
        let Ok(port) = socket.local_addr().map(|a| a.port()) else { return unavailable("no free UDP port") };
        // ffmpeg takes the stream identifier as a signed number, so keep it
        // positive, and never zero.
        let ssrc = (u32::from_le_bytes(random_bytes()) & 0x7fff_ffff).max(1);
        let response = SetupResponse {
            request: &request,
            local_ip,
            video_port: port,
            // No audio is sent yet; the same port absorbs anything addressed to it.
            audio_port: port,
            video_ssrc: ssrc,
            audio_ssrc: ssrc ^ 0x0100_0000,
        }
        .encode();
        self.state.lock().unwrap().pending = Some(Pending { request, ssrc, connection, socket });
        Ok(Some(response))
    }

    fn selected(self: &Arc<Self>, value: &Value) -> Result<Option<Value>, i32> {
        let selected = parse_selected(value).ok_or(status::INVALID_VALUE)?;
        match selected.command {
            Command::Start => {
                let video = selected.video.ok_or(status::INVALID_VALUE)?;
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
                self.start(pending, video);
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

    fn start(self: &Arc<Self>, pending: Pending, video: SelectedVideo) {
        let Some(input) = self.source.input_args(video.width) else {
            tracing::warn!("{}: the camera became unreachable before the stream started", self.name);
            return;
        };
        let args = ffmpeg_args(&input, &pending.request, &video, pending.ssrc);
        let mut command = tokio::process::Command::new(&self.ffmpeg);
        command.args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                tracing::error!("{}: could not start {}: {e}", self.name, self.ffmpeg.display());
                return;
            }
        };
        tracing::info!(
            "{}: streaming {}x{} at {} fps, {} kbps to {}",
            self.name,
            video.width,
            video.height,
            video.fps,
            video.max_bitrate_kbps,
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

        let stream = self.clone();
        let stderr = child.stderr.take();
        tokio::spawn(async move {
            // Keep the reserved port for as long as the stream lives.
            let _socket = pending.socket;
            if let Some(stderr) = stderr {
                let name = stream.name.clone();
                tokio::spawn(async move {
                    let mut lines = BufReader::new(stderr).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        tracing::warn!("{name}: ffmpeg: {line}");
                    }
                });
            }
            tokio::select! {
                exit = child.wait() => match exit {
                    Ok(code) if code.success() => tracing::info!("{}: stream ended", stream.name),
                    Ok(code) => tracing::warn!("{}: ffmpeg stopped unexpectedly ({code})", stream.name),
                    Err(e) => tracing::warn!("{}: lost track of ffmpeg: {e}", stream.name),
                },
                // Fires when the sender is dropped, however the stream was ended.
                _ = &mut stopped => {
                    let _ = child.kill().await;
                    tracing::info!("{}: stream stopped", stream.name);
                }
            }
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

fn random_bytes() -> [u8; 4] {
    // Std's hasher seeds are random per process and per instance, which is
    // plenty for a stream identifier that only needs to be unpredictable
    // enough not to collide.
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
    (hasher.finish() as u32).to_le_bytes()
}

/// The ffmpeg command line for one stream. `input` comes from the video
/// source; everything after it is determined by what the controller asked.
fn ffmpeg_args(input: &[String], request: &SetupRequest, video: &SelectedVideo, ssrc: u32) -> Vec<String> {
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

    let mut args = fixed(&["-hide_banner", "-loglevel", "error", "-nostdin"]);
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
    args
}

#[cfg(test)]
mod tests {
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
        let input = vec!["-i".to_owned(), "SOURCE".to_owned()];
        let args = ffmpeg_args(&input, &request("10.0.0.9", 50000), &video(1280, 720), 12345);
        let line = args.join(" ");
        for expected in [
            "-i SOURCE",
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
        let v6 = ffmpeg_args(&input, &request("fe80::1", 50000), &video(320, 240), 1);
        assert!(v6.last().unwrap().starts_with("srtp://[fe80::1]:50000?"));
    }

    struct TestPattern;

    impl VideoSource for TestPattern {
        fn input_args(&self, _width: u16) -> Option<Vec<String>> {
            Some(["-re", "-f", "lavfi", "-i", "testsrc=size=640x480:rate=30"].iter().map(|s| s.to_string()).collect())
        }
    }

    struct Offline;

    impl VideoSource for Offline {
        fn input_args(&self, _width: u16) -> Option<Vec<String>> {
            None
        }
    }

    fn camera(source: Arc<dyn VideoSource>, ffmpeg: &Path) -> (Arc<Database>, StreamIds) {
        let info = Info { name: "Cam", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
        let mut accessory = Accessory::new(2, &info);
        let ids = add_stream_service(&mut accessory, 200, &resolutions(640, 480));
        let db = Database::new();
        db.add(accessory);
        install(&db, 2, ids, "Cam", source, ffmpeg);
        (db, ids)
    }

    fn context(connection: u64) -> WriteContext {
        WriteContext { connection, local_ip: "127.0.0.1".parse().unwrap(), peer_ip: "127.0.0.1".parse().unwrap() }
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

    /// Runs a real ffmpeg with a test pattern and checks encrypted RTP
    /// actually arrives. Skipped where ffmpeg is not installed.
    #[tokio::test]
    async fn real_ffmpeg_delivers_rtp_and_stops_on_end_or_disconnect() {
        let Some(ffmpeg) = find_ffmpeg() else {
            eprintln!("ffmpeg not installed; skipping");
            return;
        };
        let (db, ids) = camera(Arc::new(TestPattern), &ffmpeg);
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = receiver.local_addr().unwrap().port();
        let (setup, start) = controller_writes(port, 1);

        db.write(2, ids.setup, &setup, &context(7)).unwrap();
        let answer = db.read(2, ids.setup).unwrap();
        assert_eq!(harbormaster_hap::camera::test_support::setup_status(&answer), Some(0));
        db.write(2, ids.selected, &start, &context(7)).unwrap();
        assert_eq!(db.read(2, ids.status).unwrap(), camera::streaming_status(camera::STATUS_IN_USE));

        // Control packets (sender reports, types 200 to 204) share the port
        // with video, so read until a video packet shows up.
        let mut packet = [0u8; 2048];
        let video_packet = async {
            loop {
                let n = receiver.recv(&mut packet).await.unwrap();
                assert!(n > 12, "packet too short to be RTP");
                assert_eq!(packet[0] >> 6, 2, "RTP version");
                if !(200..=204).contains(&packet[1]) {
                    return packet[1] & 0x7f;
                }
            }
        };
        let payload_type = tokio::time::timeout(Duration::from_secs(15), video_packet)
            .await
            .expect("no video arrived from ffmpeg");
        assert_eq!(payload_type, 99, "the negotiated payload type");

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
