//! The HomeKit camera live-stream negotiation.
//!
//! A controller starts a stream in two writes. `SetupEndpoints` tells the
//! accessory where to send encrypted video and audio and with which keys,
//! and the accessory answers with its own address and stream identifiers.
//! `SelectedRTPStreamConfiguration` then picks the resolution, bitrate and
//! codec settings and says start (or stop).
//!
//! All of these values are TLV8 structures, base64-encoded in JSON.

use std::net::IpAddr;

use serde_json::{json, Value};

use crate::crypto::{base64_decode, base64_encode};
use crate::model::{Characteristic, Format};
use crate::tlv::Tlv;

/// Type identifiers for the camera stream service and its characteristics.
pub mod kind {
    pub const CAMERA_RTP_STREAM_MANAGEMENT: &str = "110";
    pub const STREAMING_STATUS: &str = "120";
    pub const SUPPORTED_VIDEO_STREAM_CONFIGURATION: &str = "114";
    pub const SUPPORTED_AUDIO_STREAM_CONFIGURATION: &str = "115";
    pub const SUPPORTED_RTP_CONFIGURATION: &str = "116";
    pub const SELECTED_RTP_STREAM_CONFIGURATION: &str = "117";
    pub const SETUP_ENDPOINTS: &str = "118";
}

/// The only SRTP suite offered: AES-128 counter mode with HMAC-SHA1-80.
pub const SRTP_AES_CM_128_HMAC_SHA1_80: u8 = 0;

pub const STATUS_AVAILABLE: u8 = 0;
pub const STATUS_IN_USE: u8 = 1;

const H264: u8 = 0;
const OPUS: u8 = 3;

/// Separates repeated items of the same type in a TLV8 list.
fn separator(tlv: &mut Tlv) {
    tlv.push(0x00, &[]);
}

fn encode(tlv: &Tlv) -> String {
    base64_encode(&tlv.encode())
}

fn tlv_value(tlv: &Tlv) -> Value {
    json!(encode(tlv))
}

fn decode(value: &Value) -> Option<Tlv> {
    Tlv::decode(&base64_decode(value.as_str()?)?).ok()
}

fn nested(tlv: &Tlv, ty: u8) -> Option<Tlv> {
    Tlv::decode(tlv.get(ty)?).ok()
}

fn u16_le(tlv: &Tlv, ty: u8) -> Option<u16> {
    Some(u16::from_le_bytes(tlv.get(ty)?.try_into().ok()?))
}

pub fn streaming_status(status: u8) -> Value {
    tlv_value(&Tlv::new().with(0x01, &[status]))
}

/// Advertises H.264 at every profile and level HomeKit knows, for the given
/// `(width, height, frames per second)` choices.
pub fn supported_video(resolutions: &[(u16, u16, u8)]) -> Value {
    let mut parameters = Tlv::new();
    // Profiles: baseline, main, high.
    for (i, profile) in [0u8, 1, 2].iter().enumerate() {
        if i > 0 {
            separator(&mut parameters);
        }
        parameters.push(0x01, &[*profile]);
    }
    // Levels: 3.1, 3.2, 4.0.
    for (i, level) in [0u8, 1, 2].iter().enumerate() {
        if i > 0 {
            separator(&mut parameters);
        }
        parameters.push(0x02, &[*level]);
    }
    // Packetization mode: non-interleaved.
    parameters.push(0x03, &[0]);

    let mut codec = Tlv::new().with(0x01, &[H264]).with(0x02, &parameters.encode());
    for (i, (width, height, fps)) in resolutions.iter().enumerate() {
        if i > 0 {
            separator(&mut codec);
        }
        let attributes = Tlv::new()
            .with(0x01, &width.to_le_bytes())
            .with(0x02, &height.to_le_bytes())
            .with(0x03, &[*fps]);
        codec.push(0x03, &attributes.encode());
    }
    tlv_value(&Tlv::new().with(0x01, &codec.encode()))
}

/// Advertises Opus at 24 kHz and 16 kHz, variable bitrate, mono. HomeKit
/// requires an audio offer even from a camera that sends no audio.
pub fn supported_audio() -> Value {
    let mut out = Tlv::new();
    // Sample rates: 2 is 24 kHz, 1 is 16 kHz.
    for (i, rate) in [2u8, 1].iter().enumerate() {
        if i > 0 {
            separator(&mut out);
        }
        let parameters = Tlv::new().with(0x01, &[1]).with(0x02, &[0]).with(0x03, &[*rate]);
        let codec = Tlv::new().with(0x01, &[OPUS]).with(0x02, &parameters.encode());
        out.push(0x01, &codec.encode());
    }
    // No comfort noise.
    out.push(0x02, &[0]);
    tlv_value(&out)
}

pub fn supported_rtp() -> Value {
    tlv_value(&Tlv::new().with(0x02, &[SRTP_AES_CM_128_HMAC_SHA1_80]))
}

/// The characteristics of one stream management service, in the order
/// `selected configuration, setup endpoints, status, audio, rtp, video`.
pub fn stream_characteristics(resolutions: &[(u16, u16, u8)]) -> Vec<Characteristic> {
    let tlv = |kind, value| Characteristic::constant(kind, Format::Tlv8, value);
    let empty = || json!("");
    vec![
        Characteristic { writable: true, ..tlv(kind::SELECTED_RTP_STREAM_CONFIGURATION, empty()) },
        Characteristic { writable: true, ..tlv(kind::SETUP_ENDPOINTS, empty()) },
        Characteristic { notifies: true, ..tlv(kind::STREAMING_STATUS, streaming_status(STATUS_AVAILABLE)) },
        tlv(kind::SUPPORTED_AUDIO_STREAM_CONFIGURATION, supported_audio()),
        tlv(kind::SUPPORTED_RTP_CONFIGURATION, supported_rtp()),
        tlv(kind::SUPPORTED_VIDEO_STREAM_CONFIGURATION, supported_video(resolutions)),
    ]
}

/// SRTP keying material for one direction of one stream.
#[derive(Clone, PartialEq, Eq)]
pub struct Srtp {
    pub suite: u8,
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
}

impl std::fmt::Debug for Srtp {
    // Keys must never reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Srtp {{ suite: {}, key: <{} bytes>, salt: <{} bytes> }}", self.suite, self.key.len(), self.salt.len())
    }
}

impl Srtp {
    fn parse(tlv: &Tlv) -> Option<Self> {
        Some(Self { suite: tlv.get_u8(0x01)?, key: tlv.get(0x02)?.to_vec(), salt: tlv.get(0x03)?.to_vec() })
    }

    fn encode(&self) -> Vec<u8> {
        Tlv::new().with(0x01, &[self.suite]).with(0x02, &self.key).with(0x03, &self.salt).encode()
    }

    /// Key followed by salt, base64-encoded, as SRTP tools expect it.
    pub fn key_material(&self) -> String {
        base64_encode(&[self.key.as_slice(), self.salt.as_slice()].concat())
    }
}

/// A controller's request to prepare a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupRequest {
    pub session_id: [u8; 16],
    pub controller_ip: IpAddr,
    pub video_port: u16,
    pub audio_port: u16,
    pub video_srtp: Srtp,
    pub audio_srtp: Srtp,
}

pub fn parse_setup(value: &Value) -> Option<SetupRequest> {
    let tlv = decode(value)?;
    let address = nested(&tlv, 0x03)?;
    Some(SetupRequest {
        session_id: tlv.get(0x01)?.try_into().ok()?,
        controller_ip: std::str::from_utf8(address.get(0x02)?).ok()?.parse().ok()?,
        video_port: u16_le(&address, 0x03)?,
        audio_port: u16_le(&address, 0x04)?,
        video_srtp: Srtp::parse(&nested(&tlv, 0x04)?)?,
        audio_srtp: Srtp::parse(&nested(&tlv, 0x05)?)?,
    })
}

/// The accessory's answer to a [`SetupRequest`].
pub struct SetupResponse<'a> {
    pub request: &'a SetupRequest,
    /// This accessory's address as the controller reached it.
    pub local_ip: IpAddr,
    /// Local ports the controller may send control traffic to.
    pub video_port: u16,
    pub audio_port: u16,
    pub video_ssrc: u32,
    pub audio_ssrc: u32,
}

impl SetupResponse<'_> {
    pub fn encode(&self) -> Value {
        let version = if self.local_ip.is_ipv6() { 1u8 } else { 0 };
        let address = Tlv::new()
            .with(0x01, &[version])
            .with(0x02, self.local_ip.to_string().as_bytes())
            .with(0x03, &self.video_port.to_le_bytes())
            .with(0x04, &self.audio_port.to_le_bytes());
        tlv_value(
            &Tlv::new()
                .with(0x01, &self.request.session_id)
                .with(0x02, &[0]) // success
                .with(0x03, &address.encode())
                .with(0x04, &self.request.video_srtp.encode())
                .with(0x05, &self.request.audio_srtp.encode())
                .with(0x06, &self.video_ssrc.to_le_bytes())
                .with(0x07, &self.audio_ssrc.to_le_bytes()),
        )
    }
}

/// The answer when a stream cannot be prepared.
pub fn setup_error(session_id: &[u8; 16]) -> Value {
    // Status 2 is a generic error.
    tlv_value(&Tlv::new().with(0x01, session_id).with(0x02, &[2]))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    End,
    Start,
    Suspend,
    Resume,
    Reconfigure,
}

/// The video settings a controller chose for a stream.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedVideo {
    /// 0 baseline, 1 main, 2 high.
    pub profile: u8,
    /// 0 is level 3.1, 1 is 3.2, 2 is 4.0.
    pub level: u8,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub payload_type: u8,
    pub max_bitrate_kbps: u16,
    /// Largest packet the controller wants, if it said.
    pub mtu: Option<u16>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Selected {
    pub session_id: [u8; 16],
    pub command: Command,
    /// Present for start and reconfigure.
    pub video: Option<SelectedVideo>,
}

pub fn parse_selected(value: &Value) -> Option<Selected> {
    let tlv = decode(value)?;
    let control = nested(&tlv, 0x01)?;
    let command = match control.get_u8(0x02)? {
        0 => Command::End,
        1 => Command::Start,
        2 => Command::Suspend,
        3 => Command::Resume,
        4 => Command::Reconfigure,
        _ => return None,
    };
    let video = nested(&tlv, 0x02).and_then(|video| {
        let parameters = nested(&video, 0x02)?;
        let attributes = nested(&video, 0x03)?;
        let rtp = nested(&video, 0x04)?;
        Some(SelectedVideo {
            profile: parameters.get_u8(0x01)?,
            level: parameters.get_u8(0x02)?,
            width: u16_le(&attributes, 0x01)?,
            height: u16_le(&attributes, 0x02)?,
            fps: attributes.get_u8(0x03)?,
            payload_type: rtp.get_u8(0x01)?,
            max_bitrate_kbps: u16_le(&rtp, 0x03)?,
            mtu: u16_le(&rtp, 0x05),
        })
    });
    Some(Selected { session_id: control.get(0x01)?.try_into().ok()?, command, video })
}

/// Builds the values a controller would write, for tests of code that sits
/// on top of this module. Not part of the stable interface.
#[doc(hidden)]
pub mod test_support {
    use super::*;

    pub fn setup_value(ip: &str, video_port: u16) -> Value {
        let srtp = Srtp { suite: SRTP_AES_CM_128_HMAC_SHA1_80, key: vec![1; 16], salt: vec![2; 14] };
        let address = Tlv::new()
            .with(0x01, &[if ip.contains(':') { 1 } else { 0 }])
            .with(0x02, ip.as_bytes())
            .with(0x03, &video_port.to_le_bytes())
            .with(0x04, &(video_port + 2).to_le_bytes());
        tlv_value(
            &Tlv::new()
                .with(0x01, &[7u8; 16])
                .with(0x03, &address.encode())
                .with(0x04, &srtp.encode())
                .with(0x05, &srtp.encode()),
        )
    }

    pub fn selected_value(command: u8, width: u16, height: u16, fps: u8, kbps: u16) -> Value {
        let control = Tlv::new().with(0x01, &[7u8; 16]).with(0x02, &[command]);
        let parameters = Tlv::new().with(0x01, &[1]).with(0x02, &[2]).with(0x03, &[0]);
        let attributes =
            Tlv::new().with(0x01, &width.to_le_bytes()).with(0x02, &height.to_le_bytes()).with(0x03, &[fps]);
        let rtp = Tlv::new()
            .with(0x01, &[99])
            .with(0x02, &1u32.to_le_bytes())
            .with(0x03, &kbps.to_le_bytes())
            .with(0x04, &0.5f32.to_le_bytes())
            .with(0x05, &1378u16.to_le_bytes());
        let video = Tlv::new()
            .with(0x01, &[H264])
            .with(0x02, &parameters.encode())
            .with(0x03, &attributes.encode())
            .with(0x04, &rtp.encode());
        tlv_value(&Tlv::new().with(0x01, &control.encode()).with(0x02, &video.encode()))
    }

    /// The status field of a setup response: 0 is success.
    pub fn setup_status(value: &Value) -> Option<u8> {
        decode(value)?.get_u8(0x02)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srtp(fill: u8) -> Srtp {
        Srtp { suite: SRTP_AES_CM_128_HMAC_SHA1_80, key: vec![fill; 16], salt: vec![fill + 1; 14] }
    }

    fn setup_request_value(ip: &str) -> Value {
        let address = Tlv::new()
            .with(0x01, &[if ip.contains(':') { 1 } else { 0 }])
            .with(0x02, ip.as_bytes())
            .with(0x03, &50000u16.to_le_bytes())
            .with(0x04, &50002u16.to_le_bytes());
        tlv_value(
            &Tlv::new()
                .with(0x01, &[7u8; 16])
                .with(0x03, &address.encode())
                .with(0x04, &srtp(1).encode())
                .with(0x05, &srtp(3).encode()),
        )
    }

    #[test]
    fn parses_setup_and_builds_matching_response() {
        let request = parse_setup(&setup_request_value("10.0.0.9")).unwrap();
        assert_eq!(request.session_id, [7u8; 16]);
        assert_eq!(request.controller_ip, "10.0.0.9".parse::<IpAddr>().unwrap());
        assert_eq!((request.video_port, request.audio_port), (50000, 50002));
        assert_eq!((request.video_srtp.clone(), request.audio_srtp.clone()), (srtp(1), srtp(3)));

        let response = SetupResponse {
            request: &request,
            local_ip: "10.0.0.2".parse().unwrap(),
            video_port: 40000,
            audio_port: 40002,
            video_ssrc: 0x1122_3344,
            audio_ssrc: 0x5566_7788,
        }
        .encode();
        let tlv = decode(&response).unwrap();
        assert_eq!(tlv.get(0x01), Some(&[7u8; 16][..]));
        assert_eq!(tlv.get_u8(0x02), Some(0));
        let address = nested(&tlv, 0x03).unwrap();
        assert_eq!(address.get(0x02), Some(&b"10.0.0.2"[..]));
        assert_eq!(u16_le(&address, 0x03), Some(40000));
        // The controller's keys are echoed back.
        assert_eq!(Srtp::parse(&nested(&tlv, 0x04).unwrap()).unwrap(), srtp(1));
        assert_eq!(tlv.get(0x06), Some(&0x1122_3344u32.to_le_bytes()[..]));
    }

    #[test]
    fn parses_ipv6_setup_and_rejects_garbage() {
        let request = parse_setup(&setup_request_value("fe80::1")).unwrap();
        assert!(request.controller_ip.is_ipv6());
        assert!(parse_setup(&json!("not base64!")).is_none());
        assert!(parse_setup(&json!("")).is_none());
        assert!(parse_setup(&json!(5)).is_none());
        assert_eq!(decode(&setup_error(&[7u8; 16])).unwrap().get_u8(0x02), Some(2));
    }

    fn selected_value(command: u8, with_video: bool) -> Value {
        let control = Tlv::new().with(0x01, &[7u8; 16]).with(0x02, &[command]);
        let mut tlv = Tlv::new().with(0x01, &control.encode());
        if with_video {
            let parameters = Tlv::new().with(0x01, &[1]).with(0x02, &[2]).with(0x03, &[0]);
            let attributes =
                Tlv::new().with(0x01, &1280u16.to_le_bytes()).with(0x02, &720u16.to_le_bytes()).with(0x03, &[30]);
            let rtp = Tlv::new()
                .with(0x01, &[99])
                .with(0x02, &1u32.to_le_bytes())
                .with(0x03, &299u16.to_le_bytes())
                .with(0x04, &0.5f32.to_le_bytes())
                .with(0x05, &1378u16.to_le_bytes());
            let video = Tlv::new()
                .with(0x01, &[H264])
                .with(0x02, &parameters.encode())
                .with(0x03, &attributes.encode())
                .with(0x04, &rtp.encode());
            tlv.push(0x02, &video.encode());
        }
        tlv_value(&tlv)
    }

    #[test]
    fn parses_start_and_end_commands() {
        let start = parse_selected(&selected_value(1, true)).unwrap();
        assert_eq!(start.command, Command::Start);
        assert_eq!(
            start.video,
            Some(SelectedVideo {
                profile: 1,
                level: 2,
                width: 1280,
                height: 720,
                fps: 30,
                payload_type: 99,
                max_bitrate_kbps: 299,
                mtu: Some(1378),
            })
        );
        let end = parse_selected(&selected_value(0, false)).unwrap();
        assert_eq!((end.command, end.video), (Command::End, None));
        assert!(parse_selected(&selected_value(9, false)).is_none());
    }

    #[test]
    fn supported_video_lists_every_resolution_separately() {
        let value = supported_video(&[(1920, 1080, 30), (1280, 720, 30), (320, 240, 15)]);
        let codec = nested(&decode(&value).unwrap(), 0x01).unwrap();
        assert_eq!(codec.get_u8(0x01), Some(H264));
        // Three attribute entries with two separators between them.
        let bytes = codec.encode();
        let decoded = Tlv::decode(&bytes).unwrap();
        let first = nested(&decoded, 0x03).unwrap();
        assert_eq!((u16_le(&first, 0x01), u16_le(&first, 0x02), first.get_u8(0x03)), (Some(1920), Some(1080), Some(30)));
        assert!(bytes.windows(2).filter(|w| *w == [0x00, 0x00]).count() >= 2);
        assert_eq!(stream_characteristics(&[(1280, 720, 30)]).len(), 6);
    }

    #[test]
    fn srtp_debug_output_hides_keys() {
        let text = format!("{:?}", srtp(0xAB));
        assert!(!text.to_lowercase().contains("ab"), "{text}");
    }
}
