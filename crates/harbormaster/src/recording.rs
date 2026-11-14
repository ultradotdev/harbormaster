//! HomeKit Secure Video recording.
//!
//! While recording is switched on for a camera in the Home app, its video
//! is kept in a short rolling buffer in memory. When something happens (the
//! camera's motion sensor or doorbell fires), a home hub asks for a
//! recording. An ffmpeg process is then started on the buffered video plus
//! everything that follows, re-encodes it with the GPU into the pieces the
//! hub asked for, and those are sent over a data stream until the hub says
//! stop. Nothing is written to disk.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use harbormaster_hap::datastream::{DataStreams, RecordingSource, Refusal};
use harbormaster_hap::model::status;
use harbormaster_hap::recording::{self, kind, SelectedRecording};
use harbormaster_hap::{Accessory, Database, SnapshotReason};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc};

use crate::fmp4::{self, Piece, Splitter};
use crate::video::{Repeats, VideoSource};

const STATE_FILE: &str = "recording.json";
/// How much video is kept. A recording must start on a keyframe from
/// before the event; a hub can take several seconds to ask after the event
/// began, and keyframes can be five seconds apart.
const KEEP: Duration = Duration::from_secs(20);
/// An event older than this is not what a new request is about.
const EVENT_WINDOW: Duration = Duration::from_secs(15);
/// Stops a camera's buffer from growing without limit if its timing is off.
const MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;
/// No single recording runs longer than this, whatever the hub does.
const MAX_RECORDING: Duration = Duration::from_secs(10 * 60);

/// Instance ids of the recording services of one camera.
#[derive(Clone, Copy, Debug)]
pub struct RecordingIds {
    event_snapshots: u64,
    camera_on: u64,
    periodic_snapshots: u64,
    active: u64,
    selected: u64,
    audio: u64,
    transport_setup: u64,
}

/// Adds the three recording services at fixed instance ids: `base` for the
/// camera's switches, `base + 10` for recording management and `base + 20`
/// for the data stream.
pub fn add_services(
    accessory: &mut Accessory,
    base: u64,
    offered: &[(u16, u16, u8)],
    triggers: u8,
    motion_service: Option<u64>,
) -> RecordingIds {
    let mode = accessory.add_service_at(base, kind::CAMERA_OPERATING_MODE, false, recording::operating_mode_characteristics());
    let management = accessory.add_service_at(
        base + 10,
        kind::CAMERA_RECORDING_MANAGEMENT,
        false,
        recording::recording_characteristics(offered, triggers),
    );
    let transport = accessory.add_service_at(
        base + 20,
        kind::DATA_STREAM_TRANSPORT_MANAGEMENT,
        false,
        recording::transport_characteristics(),
    );
    // The hub looks for the data stream and the sensor that triggers
    // recordings through these links.
    accessory.link(base + 10, base + 20);
    if let Some(motion) = motion_service {
        accessory.link(base + 10, motion);
    }
    RecordingIds {
        event_snapshots: mode[0],
        camera_on: mode[1],
        periodic_snapshots: mode[2],
        active: management[0],
        selected: management[4],
        audio: management[5],
        transport_setup: transport[0],
    }
}

/// What the Home app has set for one camera, kept across restarts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    active: bool,
    audio: bool,
    camera_on: bool,
    event_snapshots: bool,
    periodic_snapshots: bool,
    /// Whether live view is allowed, as Home's streaming choice sets it.
    streaming: bool,
    /// The hub's chosen recording format, as it wrote it.
    selected: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            active: false,
            audio: false,
            camera_on: true,
            event_snapshots: true,
            periodic_snapshots: true,
            streaming: true,
            selected: String::new(),
        }
    }
}

impl Settings {
    fn format(&self) -> Option<SelectedRecording> {
        recording::parse_selected(&json!(self.selected))
    }

    /// Whether video should be buffered, and so whether a hub may record.
    fn wanted(&self) -> Option<SelectedRecording> {
        self.format().filter(|_| self.active && self.camera_on)
    }
}

struct Segment {
    at: Instant,
    data: Bytes,
    keyframe: bool,
}

/// The last few seconds of a camera's video.
struct Buffer {
    /// The MP4 header every reader needs first.
    init: Option<Bytes>,
    video_track: Option<u32>,
    segments: VecDeque<Segment>,
    bytes: usize,
    /// Each new segment, for recordings in progress.
    live: broadcast::Sender<Bytes>,
}

impl Buffer {
    fn new() -> Self {
        Self { init: None, video_track: None, segments: VecDeque::new(), bytes: 0, live: broadcast::channel(256).0 }
    }

    fn clear(&mut self) {
        self.init = None;
        self.video_track = None;
        self.segments.clear();
        self.bytes = 0;
    }

    fn push(&mut self, data: Bytes, now: Instant) {
        if self.init.is_none() {
            self.video_track = fmp4::video_track(&data);
            self.init = Some(data);
            return;
        }
        let keyframe = self.video_track.is_some_and(|track| fmp4::has_keyframe(&data, track));
        self.bytes += data.len();
        self.segments.push_back(Segment { at: now, data: data.clone(), keyframe });
        while self.segments.front().is_some_and(|s| now.duration_since(s.at) > KEEP || self.bytes > MAX_BUFFER_BYTES) {
            self.bytes -= self.segments.pop_front().map_or(0, |s| s.data.len());
        }
        // Nobody listening is the normal case.
        let _ = self.live.send(data);
    }

    /// The header and the buffered video a recording should begin with:
    /// from the newest keyframe at least `preroll` old, else the oldest
    /// keyframe there is, else nothing but what comes next.
    fn start(&self, preroll: Duration, now: Instant) -> Option<(Bytes, Vec<Bytes>, broadcast::Receiver<Bytes>)> {
        let init = self.init.clone()?;
        let keyframes = || self.segments.iter().enumerate().filter(|(_, s)| s.keyframe);
        let from = keyframes()
            .rfind(|(_, s)| now.duration_since(s.at) >= preroll)
            .or_else(|| keyframes().next())
            .map_or(self.segments.len(), |(i, _)| i);
        let backlog = self.segments.iter().skip(from).map(|s| s.data.clone()).collect();
        Some((init, backlog, self.live.subscribe()))
    }
}

struct Camera {
    name: String,
    /// Identifies the camera in the settings file.
    key: String,
    source: Arc<dyn VideoSource>,
    buffer: Mutex<Buffer>,
    /// When the camera last began to see motion or was rung.
    event_at: Mutex<Option<Instant>>,
    /// The task filling the buffer, while recording is switched on.
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Camera {
    /// Starts or stops buffering to match the settings.
    fn refresh(self: &Arc<Self>, settings: &Settings) {
        let mut task = self.task.lock().unwrap();
        if let Some(running) = task.take() {
            running.abort();
        }
        self.buffer.lock().unwrap().clear();
        let Some(format) = settings.wanted() else { return };
        let camera = self.clone();
        *task = Some(tokio::spawn(async move {
            let mut delay = Duration::from_secs(2);
            loop {
                let started = Instant::now();
                if let Some(mut feed) = camera.source.open(format.width) {
                    while let Some(data) = feed.recv().await {
                        camera.buffer.lock().unwrap().push(data, Instant::now());
                    }
                }
                // The feed ended or the console is unreachable. What was
                // buffered cannot be joined to what comes next.
                camera.buffer.lock().unwrap().clear();
                delay = if started.elapsed() > Duration::from_secs(60) {
                    Duration::from_secs(2)
                } else {
                    (delay * 2).min(Duration::from_secs(60))
                };
                tokio::time::sleep(delay).await;
            }
        }));
    }
}

/// Owns every camera's buffer and answers home hubs that ask for recordings.
pub struct Recorder {
    state_path: PathBuf,
    ffmpeg: PathBuf,
    settings: Mutex<HashMap<String, Settings>>,
    cameras: Mutex<HashMap<u64, Arc<Camera>>>,
    streams: Mutex<Option<Arc<DataStreams>>>,
}

impl Recorder {
    /// Must be called from within the async runtime.
    pub fn new(state_dir: &Path, ffmpeg: &Path) -> Arc<Self> {
        let state_path = state_dir.join(STATE_FILE);
        let settings = match std::fs::read(&state_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable {}: {e}", state_path.display());
                HashMap::new()
            }),
            Err(_) => HashMap::new(),
        };
        let recorder = Arc::new(Self {
            state_path,
            ffmpeg: ffmpeg.to_owned(),
            settings: Mutex::new(settings),
            cameras: Mutex::new(HashMap::new()),
            streams: Mutex::new(None),
        });
        match DataStreams::start(recorder.clone()) {
            Ok(streams) => *recorder.streams.lock().unwrap() = Some(streams),
            Err(e) => tracing::error!("recording is unavailable: could not open a port for data streams: {e}"),
        }
        recorder
    }

    fn save(&self, settings: &HashMap<String, Settings>) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let temporary = self.state_path.with_extension("json.tmp");
        let written = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other).and_then(|bytes| {
            let mut file =
                std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.state_path)
        });
        if let Err(e) = written {
            tracing::warn!("could not save {}: {e}", self.state_path.display());
        }
    }

    fn settings_for(&self, aid: u64) -> Option<Settings> {
        let key = self.cameras.lock().unwrap().get(&aid)?.key.clone();
        Some(self.settings.lock().unwrap().get(&key).cloned().unwrap_or_default())
    }

    /// Why HomeKit's switches forbid watching this camera live, if they do.
    pub fn live_view_refusal(&self, aid: u64) -> Option<&'static str> {
        let settings = self.settings_for(aid)?;
        if !settings.camera_on {
            Some("the camera is switched off in HomeKit")
        } else if !settings.streaming {
            Some("streaming is switched off for this camera in HomeKit")
        } else {
            None
        }
    }

    /// Whether HomeKit's switches allow a still image for this purpose.
    pub fn snapshot_allowed(&self, aid: u64, reason: SnapshotReason) -> bool {
        let Some(settings) = self.settings_for(aid) else { return true };
        settings.camera_on
            && match reason {
                SnapshotReason::Periodic => settings.periodic_snapshots,
                SnapshotReason::Event => settings.event_snapshots,
                SnapshotReason::Unspecified => true,
            }
    }

    /// Forgets a camera that is no longer published and stops buffering it.
    pub fn remove(&self, aid: u64) {
        if let Some(camera) = self.cameras.lock().unwrap().remove(&aid) {
            if let Some(task) = camera.task.lock().unwrap().take() {
                task.abort();
            }
        }
    }

    /// Notes that a camera has just begun to see motion or been rung, so
    /// that a recording asked for moments later can reach back to before it.
    pub fn event_started(&self, aid: u64) {
        if let Some(camera) = self.cameras.lock().unwrap().get(&aid) {
            *camera.event_at.lock().unwrap() = Some(Instant::now());
        }
    }

    /// Connects a camera's recording services to its video. `key` names the
    /// camera in the settings file. Must be called from within the async
    /// runtime, after the accessory is in the database.
    #[allow(clippy::too_many_arguments)]
    pub fn install(
        self: &Arc<Self>,
        db: &Arc<Database>,
        aid: u64,
        ids: RecordingIds,
        name: &str,
        key: &str,
        source: Arc<dyn VideoSource>,
        stream_switches: &[u64],
    ) {
        let camera = Arc::new(Camera {
            name: name.to_owned(),
            key: key.to_owned(),
            source,
            buffer: Mutex::new(Buffer::new()),
            event_at: Mutex::new(None),
            task: Mutex::new(None),
        });
        if let Some(previous) = self.cameras.lock().unwrap().insert(aid, camera.clone()) {
            if let Some(task) = previous.task.lock().unwrap().take() {
                task.abort();
            }
        }

        // Show what was set before the restart.
        let settings = self.settings.lock().unwrap().get(key).cloned().unwrap_or_default();
        let on = |value: bool| json!(u8::from(value));
        db.set(aid, ids.event_snapshots, on(settings.event_snapshots));
        db.set(aid, ids.camera_on, on(settings.camera_on));
        db.set(aid, ids.periodic_snapshots, on(settings.periodic_snapshots));
        db.set(aid, ids.active, on(settings.active));
        db.set(aid, ids.audio, on(settings.audio));
        db.set(aid, ids.selected, json!(settings.selected));
        for iid in stream_switches {
            db.set(aid, *iid, on(settings.streaming));
        }
        camera.refresh(&settings);
        tracing::info!(
            "{name}: HomeKit recording is {}",
            match (settings.wanted(), settings.active, settings.format().is_some()) {
                (Some(f), ..) => format!("on at {}x{}, keeping the last {} s ready", f.width, f.height, KEEP.as_secs()),
                (None, true, false) => "switched on, but no hub has chosen a format yet".to_owned(),
                (None, true, true) => "switched on, but the camera is switched off in HomeKit".to_owned(),
                (None, false, _) => "off".to_owned(),
            }
        );

        // Each switch updates one field, is saved, and re-evaluates buffering.
        let handle = |iid: u64, apply: fn(&mut Settings, &Value) -> bool| {
            let (recorder, camera) = (self.clone(), camera.clone());
            db.on_write(
                aid,
                iid,
                Arc::new(move |value, _| {
                    let mut all = recorder.settings.lock().unwrap();
                    let settings = all.entry(camera.key.clone()).or_default();
                    let before = settings.clone();
                    if !apply(settings, value) {
                        return Err(status::INVALID_VALUE);
                    }
                    if *settings != before {
                        let (was, now) = (before.wanted().is_some(), settings.wanted().is_some());
                        if was != now {
                            tracing::info!("{}: recording switched {} in HomeKit", camera.name, if now { "on" } else { "off" });
                        }
                        let settings = settings.clone();
                        recorder.save(&all);
                        drop(all);
                        camera.refresh(&settings);
                    }
                    Ok(None)
                }),
            );
        };
        handle(ids.event_snapshots, |s, v| v.as_u64().map(|n| s.event_snapshots = n != 0).is_some());
        handle(ids.periodic_snapshots, |s, v| v.as_u64().map(|n| s.periodic_snapshots = n != 0).is_some());
        handle(ids.camera_on, |s, v| v.as_u64().map(|n| s.camera_on = n != 0).is_some());
        handle(ids.active, |s, v| v.as_u64().map(|n| s.active = n != 0).is_some());
        handle(ids.audio, |s, v| v.as_u64().map(|n| s.audio = n != 0).is_some());
        // Home sets every stream of a camera together, so one flag serves.
        for iid in stream_switches {
            handle(*iid, |s, v| v.as_u64().map(|n| s.streaming = n != 0).is_some());
        }
        handle(ids.selected, |s, v| {
            // An unusable choice is refused rather than stored.
            let usable = recording::parse_selected(v).is_some();
            if !usable {
                // Codec settings, not secrets: worth seeing in full.
                tracing::warn!("a hub chose a recording format that could not be read: {v}");
            }
            if usable {
                s.selected = v.as_str().unwrap_or_default().to_owned();
            }
            usable
        });

        let recorder = self.clone();
        let name = name.to_owned();
        db.on_write(
            aid,
            ids.transport_setup,
            Arc::new(move |value, context| {
                tracing::info!("{name}: {} is setting up a data stream", context.peer_ip);
                let salt = recording::parse_transport_setup(value).ok_or(status::INVALID_VALUE)?;
                let secret = context.shared_secret.ok_or(status::INVALID_VALUE)?;
                let streams = recorder.streams.lock().unwrap().clone().ok_or(status::INVALID_VALUE)?;
                Ok(Some(match streams.prepare(aid, &secret, &salt) {
                    Some(accessory_salt) => recording::transport_response(streams.port(), &accessory_salt),
                    None => recording::transport_busy(),
                }))
            }),
        );
    }
}

impl RecordingSource for Recorder {
    fn open(&self, aid: u64) -> Result<mpsc::Receiver<Vec<u8>>, Refusal> {
        let camera = self.cameras.lock().unwrap().get(&aid).cloned().ok_or(Refusal::Unexpected)?;
        let settings = self.settings.lock().unwrap().get(&camera.key).cloned().unwrap_or_default();
        let Some(format) = settings.wanted() else {
            tracing::info!("{}: a hub asked for a recording, but recording is switched off", camera.name);
            return Err(Refusal::NotAllowed);
        };
        // The hub asks some time after the event began, so reach back to
        // before the event itself, not just before the request.
        let now = Instant::now();
        let since_event = camera.event_at.lock().unwrap().map(|at| now.duration_since(at));
        let preroll = preroll(Duration::from_millis(format.prebuffer_ms as u64), since_event);
        let Some((init, backlog, live)) = camera.buffer.lock().unwrap().start(preroll, now) else {
            tracing::warn!("{}: a hub asked for a recording, but no video has been buffered yet", camera.name);
            return Err(Refusal::Busy);
        };
        let args = ffmpeg_args(&format, settings.audio);
        let mut child = tokio::process::Command::new(&self.ffmpeg)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                tracing::error!("{}: could not start {}: {e}", camera.name, self.ffmpeg.display());
                Refusal::Unexpected
            })?;
        tracing::info!(
            "{}: recording for HomeKit at {}x{}, {} kbps, {}, reaching back {:.0} s ({} buffered pieces){}",
            camera.name,
            format.width,
            format.height,
            format.bitrate_kbps,
            if settings.audio { "with sound" } else { "no sound" },
            preroll.as_secs_f64(),
            backlog.len(),
            match since_event.filter(|age| *age <= EVENT_WINDOW) {
                Some(age) => format!("; the hub asked {:.1} s after the event began", age.as_secs_f64()),
                None => String::new(),
            }
        );
        let (sender, receiver) = mpsc::channel(4);
        let name = camera.name.clone();
        tokio::spawn(run(child.stdin.take(), child.stdout.take(), child.stderr.take(), child, init, backlog, live, sender, name));
        Ok(receiver)
    }
}

/// How far back a recording should begin: the pre-roll the hub wants,
/// measured from when the event began if that was recent, not from when the
/// hub got round to asking.
fn preroll(wanted: Duration, since_event: Option<Duration>) -> Duration {
    wanted + since_event.filter(|age| *age <= EVENT_WINDOW).unwrap_or_default()
}

/// Feeds one ffmpeg and forwards what it produces until the hub stops
/// listening or the video runs out.
#[allow(clippy::too_many_arguments)]
async fn run(
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    mut child: tokio::process::Child,
    init: Bytes,
    backlog: Vec<Bytes>,
    mut live: broadcast::Receiver<Bytes>,
    sender: mpsc::Sender<Vec<u8>>,
    name: String,
) {
    let writer = tokio::spawn(async move {
        let Some(mut stdin) = stdin else { return };
        for data in std::iter::once(init).chain(backlog) {
            if stdin.write_all(&data).await.is_err() {
                return;
            }
        }
        // Falling behind the camera would leave a hole; end instead.
        while let Ok(data) = live.recv().await {
            if stdin.write_all(&data).await.is_err() {
                return;
            }
        }
    });
    if let Some(stderr) = stderr {
        let name = name.clone();
        tokio::spawn(async move {
            let mut seen = Repeats::default();
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if seen.first(&line) {
                    tracing::warn!("{name}: recording ffmpeg: {line}");
                }
            }
            for (line, extra) in seen.repeated() {
                tracing::warn!("{name}: recording ffmpeg: {line} ({extra} more like this)");
            }
        });
    }

    let started = Instant::now();
    let mut fragments = 0u32;
    let _recording = crate::status::global().recording(&name);
    let forward = async {
        let Some(mut stdout) = stdout else { return "ffmpeg has no output" };
        let mut splitter = Splitter::default();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let n = match stdout.read(&mut chunk).await {
                Ok(0) | Err(_) => return "the video ended",
                Ok(n) => n,
            };
            let mut pieces = Vec::new();
            if splitter.feed(&chunk[..n], &mut pieces).is_err() {
                return "ffmpeg produced something unreadable";
            }
            for piece in pieces {
                let data = match piece {
                    Piece::Header(data) => data,
                    Piece::Fragment(data) => {
                        fragments += 1;
                        data
                    }
                };
                if sender.send(data).await.is_err() {
                    return "the hub has what it wanted";
                }
            }
        }
    };
    let why = tokio::time::timeout(MAX_RECORDING, forward).await.unwrap_or("it reached the length limit");
    writer.abort();
    let _ = child.kill().await;
    tracing::info!(
        "{name}: recording ended after {:.0} s and {fragments} pieces: {why}",
        started.elapsed().as_secs_f64()
    );
}

/// The ffmpeg command line that turns buffered camera video into the
/// pieces a hub asked for.
fn ffmpeg_args(format: &SelectedRecording, audio: bool) -> Vec<String> {
    let profile = match format.profile {
        0 => "baseline",
        1 => "main",
        _ => "high",
    };
    let level = match format.level {
        0 => "3.1",
        1 => "3.2",
        _ => "4.0",
    };
    let fps = format.fps.max(1);
    let bitrate = format!("{}k", format.bitrate_kbps.max(64));
    // Every piece must begin with a keyframe, so force one at each boundary.
    let seconds = format.fragment_ms.max(1000) as f64 / 1000.0;
    let fixed = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    let mut args = fixed(&["-hide_banner", "-loglevel", "error", "-nostdin"]);
    // Software decoding, as for live view: the hardware decoder drops the
    // opening keyframe.
    args.extend(fixed(&["-f", "mp4", "-i", "pipe:0"]));
    args.extend(fixed(&["-map", "0:v:0", "-sn", "-dn"]));
    args.extend([
        "-vf".into(),
        crate::video::fit_filter(format.width, format.height),
        "-r".into(),
        fps.to_string(),
        "-codec:v".into(),
        "h264_videotoolbox".into(),
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
        "-bf".into(),
        "0".into(),
        "-force_key_frames".into(),
        format!("expr:gte(t,n_forced*{seconds})"),
        // And none in between: ffmpeg's default of one every twelve frames
        // would cut the recording into pieces a fraction of a second long.
        "-g".into(),
        ((fps as f64 * seconds).round() as u32).to_string(),
    ]);
    if audio {
        args.extend(fixed(&["-map", "0:a:0?", "-codec:a", "aac_at"]));
        args.extend([
            "-ar".into(),
            format.sample_rate_hz.to_string(),
            "-ac".into(),
            format.audio_channels.clamp(1, 2).to_string(),
            "-b:a".into(),
            format!("{}k", format.audio_bitrate_kbps.clamp(16, 128)),
        ]);
    } else {
        args.push("-an".into());
    }
    // A header with no media in it, then one self-contained piece per keyframe.
    args.extend(fixed(&["-movflags", "frag_keyframe+empty_moov+default_base_moof+skip_sidx", "-f", "mp4", "pipe:1"]));
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbormaster_hap::model::WriteContext;
    use harbormaster_hap::recording::test_support::{selected_value, transport_answer, transport_setup_value};
    use harbormaster_hap::Info;

    fn format() -> SelectedRecording {
        recording::parse_selected(&selected_value(640, 480, 30, 800, 5)).unwrap()
    }

    #[test]
    fn ffmpeg_command_follows_the_hub_choice() {
        let line = ffmpeg_args(&format(), true).join(" ");
        for expected in [
            "-f mp4 -i pipe:0",
            "-vf scale=640:480:force_original_aspect_ratio=decrease",
            "setsar=1 -r 30",
            "-codec:v h264_videotoolbox",
            "-profile:v high -level:v 4.0 -b:v 800k",
            "-force_key_frames expr:gte(t,n_forced*4) -g 120",
            "-map 0:a:0? -codec:a aac_at -ar 48000 -ac 1 -b:a 24k",
            "-movflags frag_keyframe+empty_moov+default_base_moof+skip_sidx -f mp4 pipe:1",
        ] {
            assert!(line.contains(expected), "missing {expected:?} in {line}");
        }
        let silent = ffmpeg_args(&format(), false).join(" ");
        assert!(silent.contains(" -an ") && !silent.contains("aac_at"), "{silent}");
    }

    fn settings(active: bool, camera_on: bool) -> Settings {
        Settings { active, camera_on, selected: selected_value(640, 480, 30, 800, 5).as_str().unwrap().into(), ..Settings::default() }
    }

    #[test]
    fn preroll_reaches_back_to_before_a_recent_event() {
        let four = Duration::from_secs(4);
        assert_eq!(preroll(four, None), four);
        assert_eq!(preroll(four, Some(Duration::from_secs(6))), Duration::from_secs(10));
        // An old event has nothing to do with this request.
        assert_eq!(preroll(four, Some(Duration::from_secs(120))), four);
    }

    #[test]
    fn buffering_needs_recording_on_the_camera_on_and_a_chosen_format() {
        assert!(settings(true, true).wanted().is_some());
        assert!(settings(false, true).wanted().is_none());
        assert!(settings(true, false).wanted().is_none());
        assert!(Settings { active: true, ..Settings::default() }.wanted().is_none());
    }

    /// A fragment holding one video sample, a keyframe or not.
    fn segment(keyframe: bool) -> Bytes {
        let boxed = |kind: &[u8; 4], payload: &[u8]| {
            let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
            out.extend_from_slice(kind);
            out.extend_from_slice(payload);
            out
        };
        let mut tfhd = 0u32.to_be_bytes().to_vec();
        tfhd.extend_from_slice(&1u32.to_be_bytes());
        let mut trun = 0x400u32.to_be_bytes().to_vec();
        trun.extend_from_slice(&1u32.to_be_bytes());
        trun.extend_from_slice(&(if keyframe { 0x0200_0000u32 } else { 0x0101_0000 }).to_be_bytes());
        let traf = boxed(b"traf", &[boxed(b"tfhd", &tfhd), boxed(b"trun", &trun)].concat());
        Bytes::from([boxed(b"moof", &traf), boxed(b"mdat", b"x")].concat())
    }

    fn header() -> Bytes {
        let boxed = |kind: &[u8; 4], payload: &[u8]| {
            let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
            out.extend_from_slice(kind);
            out.extend_from_slice(payload);
            out
        };
        let mut tkhd = vec![0u8; 12];
        tkhd.extend_from_slice(&1u32.to_be_bytes());
        let mut hdlr = vec![0u8; 8];
        hdlr.extend_from_slice(b"vide");
        let trak = boxed(b"trak", &[boxed(b"tkhd", &tkhd), boxed(b"mdia", &boxed(b"hdlr", &hdlr))].concat());
        Bytes::from(boxed(b"moov", &trak))
    }

    #[test]
    fn recordings_start_on_a_keyframe_old_enough_for_the_preroll() {
        let mut buffer = Buffer::new();
        let t0 = Instant::now();
        let at = |seconds: u64| t0 + Duration::from_secs(seconds);
        assert!(buffer.start(Duration::from_secs(4), t0).is_none(), "no header yet");
        buffer.push(header(), t0);
        // Keyframes at 0 s, 5 s and 10 s, with other frames between.
        for second in 0..=11 {
            buffer.push(segment(second % 5 == 0), at(second));
        }
        let backlog = |preroll, now| buffer.start(Duration::from_secs(preroll), at(now)).unwrap().1.len();
        // At 11 s with 4 s of pre-roll, the keyframe at 5 s is the newest old enough.
        assert_eq!(backlog(4, 11), 7);
        // With no pre-roll wanted, the newest keyframe will do.
        assert_eq!(backlog(0, 11), 2);
        // Nothing is old enough: fall back to the oldest keyframe.
        assert_eq!(backlog(60, 11), 12);

        // Old video is dropped, and the byte count follows.
        buffer.push(segment(false), at(60));
        assert_eq!(buffer.segments.len(), 1);
        assert_eq!(buffer.bytes, buffer.segments[0].data.len());
        // No keyframe buffered: start with only what comes next.
        assert_eq!(buffer.start(Duration::from_secs(4), at(60)).unwrap().1.len(), 0);
    }

    /// Buffers a real test feed, then asks for a recording the way a hub
    /// would and checks what comes out. Skipped where ffmpeg is missing.
    #[tokio::test]
    async fn real_ffmpeg_turns_buffered_video_into_keyframe_led_pieces() {
        let Some(ffmpeg) = crate::video::find_ffmpeg() else {
            eprintln!("ffmpeg not installed; skipping");
            return;
        };
        let dir = std::env::temp_dir().join(format!("hm-recording-{}-real", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let info = Info { name: "Cam", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
        let mut accessory = Accessory::new(2, &info);
        let ids = add_services(&mut accessory, 300, &[(640, 480, 30)], recording::TRIGGER_MOTION, None);
        let db = Database::new();
        db.add(accessory);
        let context = WriteContext {
            connection: 1,
            local_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.1".parse().unwrap(),
            shared_secret: None,
        };
        let recorder = Recorder::new(&dir, &ffmpeg);
        let source = Arc::new(crate::video::tests::TestPattern(ffmpeg.clone()));
        recorder.install(&db, 2, ids, "Cam", "cam1", source, &[]);
        db.write(2, ids.selected, &selected_value(640, 480, 30, 800, 5), &context).unwrap();
        db.write(2, ids.audio, &json!(1), &context).unwrap();
        db.write(2, ids.active, &json!(1), &context).unwrap();

        // Let a few seconds of video collect, then ask as a hub would.
        let camera = recorder.cameras.lock().unwrap().get(&2).cloned().unwrap();
        let mut waited = 0;
        while camera.buffer.lock().unwrap().segments.iter().filter(|s| s.keyframe).count() < 5 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            waited += 1;
            // Generous: under load the test feed can fail to start and is
            // retried after a pause, as a real camera's would be.
            assert!(waited < 240, "the buffer never filled with keyframes");
        }
        let asked = Instant::now();
        let mut pieces = recorder.open(2).unwrap();
        async fn next(pieces: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
            let wait = tokio::time::timeout(Duration::from_secs(20), pieces.recv());
            wait.await.expect("no piece arrived").expect("the recording ended early")
        }
        let header = next(&mut pieces).await;
        assert_eq!(&header[4..8], b"ftyp");
        let track = fmp4::video_track(&header).expect("the header names a video track");
        let first = next(&mut pieces).await;
        // The first piece comes from buffered video, so it arrives well
        // before four seconds of new video could have been recorded.
        assert!(asked.elapsed() < Duration::from_secs(3), "the first piece took {:?}", asked.elapsed());
        let before_second = Instant::now();
        let second = next(&mut pieces).await;
        // Pieces are four seconds long: the first two come from buffered
        // video, and the third has to wait for new video to be recorded.
        let third = next(&mut pieces).await;
        assert!(before_second.elapsed() > Duration::from_secs(1), "pieces are shorter than asked for");
        for piece in [&first, &second, &third] {
            assert_eq!(&piece[4..8], b"moof");
            assert!(fmp4::has_keyframe(piece, track), "each piece must hold a keyframe");
        }

        // The hub hangs up; ffmpeg and the reader go away.
        drop(pieces);
    }

    /// A stand-in camera that never produces anything.
    struct Idle;

    impl VideoSource for Idle {
        fn available(&self) -> bool {
            true
        }

        fn open(&self, _width: u16) -> Option<mpsc::Receiver<Bytes>> {
            None
        }
    }

    #[tokio::test]
    async fn settings_survive_a_restart_and_bad_choices_are_refused() {
        let dir = std::env::temp_dir().join(format!("hm-recording-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let build = || {
            let info = Info { name: "Cam", manufacturer: "m", model: "m", serial_number: "s", firmware_revision: "1" };
            let mut accessory = Accessory::new(2, &info);
            let ids = add_services(&mut accessory, 300, &[(640, 480, 30)], recording::TRIGGER_MOTION, None);
            // Stands in for a stream service's on/off switch, at id 400.
            let switch = harbormaster_hap::Characteristic {
                writable: true,
                ..harbormaster_hap::Characteristic::sensor("B0", harbormaster_hap::Format::Uint8, json!(1))
            };
            assert_eq!(accessory.add_service_at(399, "110", false, vec![switch]), [400]);
            let db = Database::new();
            db.add(accessory);
            (db, ids)
        };
        let context = WriteContext {
            connection: 1,
            local_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.1".parse().unwrap(),
            shared_secret: Some(crate::test_random::bytes()),
        };

        let (db, ids) = build();
        let recorder = Recorder::new(&dir, Path::new("/nonexistent/ffmpeg"));
        recorder.install(&db, 2, ids, "Cam", "cam1", Arc::new(Idle), &[400]);
        assert_eq!(db.read(2, ids.active), Ok(json!(0)));
        assert!(matches!(recorder.open(2), Err(Refusal::NotAllowed)));

        assert_eq!(db.write(2, ids.selected, &json!("AQID"), &context), Err(status::INVALID_VALUE));
        db.write(2, ids.selected, &selected_value(640, 480, 30, 800, 5), &context).unwrap();
        db.write(2, ids.active, &json!(1), &context).unwrap();
        db.write(2, ids.audio, &json!(true), &context).unwrap();
        // Switched on, but nothing has been buffered.
        assert!(matches!(recorder.open(2), Err(Refusal::Busy)));
        assert!(matches!(recorder.open(9), Err(Refusal::Unexpected)));

        // A hub sets up a data stream and is told where to connect.
        let hub_salt = crate::test_random::bytes::<32>();
        let answer = db.write(2, ids.transport_setup, &transport_setup_value(&hub_salt), &context).unwrap();
        let (port, salt) = transport_answer(&answer).unwrap();
        assert!(port > 0 && salt.len() == 32);
        let no_session = WriteContext { shared_secret: None, ..context };
        assert!(db.write(2, ids.transport_setup, &transport_setup_value(&hub_salt), &no_session).is_err());

        // Home's switches decide what may be seen. 400 stands in for a
        // stream's own on/off switch.
        assert_eq!(recorder.live_view_refusal(2), None);
        assert!(recorder.snapshot_allowed(2, SnapshotReason::Periodic));
        db.write(2, ids.periodic_snapshots, &json!(0), &context).unwrap();
        assert!(!recorder.snapshot_allowed(2, SnapshotReason::Periodic));
        assert!(recorder.snapshot_allowed(2, SnapshotReason::Event));
        assert!(recorder.snapshot_allowed(2, SnapshotReason::Unspecified));
        db.write(2, ids.event_snapshots, &json!(0), &context).unwrap();
        assert!(!recorder.snapshot_allowed(2, SnapshotReason::Event));
        db.write(2, 400, &json!(0), &context).unwrap();
        assert!(recorder.live_view_refusal(2).is_some_and(|why| why.contains("streaming")));
        db.write(2, 400, &json!(1), &context).unwrap();
        db.write(2, ids.camera_on, &json!(0), &context).unwrap();
        assert!(recorder.live_view_refusal(2).is_some_and(|why| why.contains("camera")));
        assert!(!recorder.snapshot_allowed(2, SnapshotReason::Unspecified));
        assert!(matches!(recorder.open(2), Err(Refusal::NotAllowed)), "a camera that is off records nothing");
        db.write(2, 400, &json!(0), &context).unwrap();
        // An accessory the recorder does not know is not its to forbid.
        assert_eq!(recorder.live_view_refusal(9), None);
        assert!(recorder.snapshot_allowed(9, SnapshotReason::Periodic));

        // After a restart the same choices are shown again.
        let (db, ids) = build();
        let recorder = Recorder::new(&dir, Path::new("/nonexistent/ffmpeg"));
        recorder.install(&db, 2, ids, "Cam", "cam1", Arc::new(Idle), &[400]);
        assert_eq!(db.read(2, 400), Ok(json!(0)), "the streaming switch is remembered");
        assert_eq!(db.read(2, ids.active), Ok(json!(1)));
        assert_eq!(db.read(2, ids.audio), Ok(json!(1)));
        assert_eq!(db.read(2, ids.selected), Ok(selected_value(640, 480, 30, 800, 5)));
        assert_eq!(db.read(2, ids.camera_on), Ok(json!(0)));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(STATE_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
