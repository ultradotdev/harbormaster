//! Pictures for the mock console's cameras, made by ffmpeg from its test
//! patterns: live feeds in the console's own framing, and still snapshots.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::fmp4::{Piece, Splitter};

const FRAME_CODEC: u8 = 248;
const FRAME_BEGIN: u8 = 249;
const FRAME_INIT: u8 = 250;
const FRAME_MOOF: u8 = 251;
const FRAME_MDAT: u8 = 254;
const FRAME_END: u8 = 255;
/// Frames carry a three-byte length.
const MAX_FRAME: usize = 0xFF_FFFF;

/// The H.264 encoder to use: the software one where ffmpeg has it, since a
/// virtual machine may have no hardware encoder.
fn encoder(ffmpeg: &Path) -> &'static str {
    static CHOSEN: OnceLock<&'static str> = OnceLock::new();
    CHOSEN.get_or_init(|| {
        let listed = std::process::Command::new(ffmpeg)
            .args(["-hide_banner", "-encoders"])
            .stderr(Stdio::null())
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("libx264"))
            .unwrap_or(false);
        if listed { "libx264" } else { "h264_videotoolbox" }
    })
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(payload);
    out
}

/// One fragment as the console sends it: its index and its media in
/// frames of their own, between a begin and an end marker.
fn wrap_fragment(fragment: &[u8]) -> Option<Vec<u8>> {
    // The media box is the last one; everything before it is the index.
    let mut offset = 0;
    let mut media_at = None;
    while let Some(size) = fragment.get(offset..offset + 4) {
        let size = u32::from_be_bytes(size.try_into().ok()?) as usize;
        if size < 8 || offset + size > fragment.len() {
            return None;
        }
        if fragment.get(offset + 4..offset + 8) == Some(b"mdat") {
            media_at = Some(offset);
        }
        offset += size;
    }
    let (index, media) = fragment.split_at(media_at?);
    if index.len() > MAX_FRAME || media.len() > MAX_FRAME {
        return None;
    }
    let mut out = frame(FRAME_BEGIN, b"");
    out.extend(frame(FRAME_MOOF, index));
    out.extend(frame(FRAME_MDAT, media));
    out.extend(frame(FRAME_END, b""));
    Some(out)
}

/// Sends a live feed of a test pattern until the viewer goes away.
pub async fn feed<S>(mut socket: WebSocketStream<S>, ffmpeg: PathBuf, pattern: &str, width: u32, height: u32, label: String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let source = format!("{pattern}=size={width}x{height}:rate=15");
    let encoder = encoder(&ffmpeg);
    let mut args = vec![
        "-hide_banner", "-loglevel", "error", "-nostdin", "-re",
        "-f", "lavfi", "-i", &source,
        "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
        "-codec:v", encoder, "-pix_fmt", "yuv420p", "-g", "15",
    ];
    if encoder == "libx264" {
        args.extend(["-preset", "ultrafast", "-tune", "zerolatency"]);
    }
    args.extend([
        "-codec:a", "aac", "-b:a", "32k",
        "-movflags", "frag_keyframe+empty_moov+default_base_moof", "-frag_duration", "100000",
        "-f", "mp4", "pipe:1",
    ]);
    let child = tokio::process::Command::new(&ffmpeg)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!("{label}: could not start ffmpeg: {e}");
            let _ = socket.close(None).await;
            return;
        }
    };
    let Some(mut stdout) = child.stdout.take() else { return };
    tracing::info!("{label}: live feed opened ({width}x{height}, {encoder})");

    let mut splitter = Splitter::default();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut sent = 0u64;
    loop {
        tokio::select! {
            read = stdout.read(&mut chunk) => {
                let n = match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut pieces = Vec::new();
                if splitter.feed(&chunk[..n], &mut pieces).is_err() {
                    tracing::warn!("{label}: ffmpeg wrote something that is not fragmented MP4");
                    break;
                }
                for piece in pieces {
                    let message = match piece {
                        Piece::Header(header) => {
                            let mut out = frame(FRAME_CODEC, b"avc1.42c01f,mp4a.40.2");
                            out.extend(frame(FRAME_INIT, &header));
                            out
                        }
                        Piece::Fragment(fragment) => match wrap_fragment(&fragment) {
                            Some(out) => out,
                            None => continue,
                        },
                    };
                    sent += message.len() as u64;
                    if socket.send(Message::Binary(Bytes::from(message))).await.is_err() {
                        tracing::info!("{label}: viewer left after {} kB", sent / 1024);
                        return;
                    }
                }
            }
            message = socket.next() => match message {
                Some(Ok(Message::Close(_)) | Err(_)) | None => {
                    tracing::info!("{label}: viewer left after {} kB", sent / 1024);
                    return;
                }
                Some(Ok(_)) => {}
            },
        }
    }
    tracing::warn!("{label}: ffmpeg stopped");
    let _ = socket.close(None).await;
}

/// One still picture of a test pattern, as JPEG.
pub async fn snapshot(ffmpeg: &Path, pattern: &str, width: u32, height: u32) -> Option<Vec<u8>> {
    let source = format!("{pattern}=size={width}x{height}:rate=1");
    let run = tokio::process::Command::new(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-nostdin", "-f", "lavfi", "-i", &source])
        .args(["-frames:v", "1", "-codec:v", "mjpeg", "-f", "image2pipe", "pipe:1"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(10), run).await.ok()?.ok()?;
    (out.status.success() && out.stdout.starts_with(&[0xFF, 0xD8])).then_some(out.stdout)
}

/// A requested picture size, kept to something ffmpeg makes quickly.
pub fn tidy_size(width: u32, height: u32) -> (u32, u32) {
    let even = |n: u32, low: u32, high: u32| n.clamp(low, high) & !1;
    (even(width, 64, 1920), even(height, 48, 1080))
}

#[cfg(test)]
mod tests {
    use super::*;
    use harbormaster_protect::{Decoder, Segment};

    fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn fragments_are_framed_the_way_the_client_reads_them() {
        let fragment = [boxed(b"styp", b"msdh"), boxed(b"moof", b"index"), boxed(b"mdat", b"media")].concat();
        let mut bytes = frame(FRAME_CODEC, b"avc1");
        bytes.extend(frame(FRAME_INIT, b"header"));
        bytes.extend(wrap_fragment(&fragment).unwrap());
        let mut out = Vec::new();
        Decoder::default().feed(&bytes, &mut out).unwrap();
        assert_eq!(
            out,
            [
                Segment::Init { codec: Some("avc1".into()), data: Bytes::from_static(b"header") },
                Segment::Media(Bytes::from(fragment.clone())),
            ]
        );
        assert_eq!(wrap_fragment(&boxed(b"moof", b"no media")), None);
        assert_eq!(wrap_fragment(&fragment[..fragment.len() - 1]), None);
    }

    #[test]
    fn sizes_are_kept_reasonable() {
        assert_eq!(tidy_size(641, 0), (640, 48));
        assert_eq!(tidy_size(100_000, 100_000), (1920, 1080));
    }
}
