//! HomeKit Secure Video: the settings through which a camera says what it
//! can record and a home hub says what it wants.
//!
//! Three services work together. *Camera operating mode* holds the
//! switches the Home app shows (camera on, snapshots on). *Recording
//! management* advertises the formats on offer and receives the hub's
//! choice. *Data stream transport* sets up the side channel the recording
//! travels over; see [`crate::datastream`].

use serde_json::{json, Value};

use crate::camera::{decode, nested, separator, tlv_value, u16_le};
use crate::model::{Characteristic, Format};
use crate::tlv::Tlv;

pub mod kind {
    pub const CAMERA_OPERATING_MODE: &str = "21A";
    pub const EVENT_SNAPSHOTS_ACTIVE: &str = "223";
    pub const HOMEKIT_CAMERA_ACTIVE: &str = "21B";
    pub const PERIODIC_SNAPSHOTS_ACTIVE: &str = "225";

    pub const CAMERA_RECORDING_MANAGEMENT: &str = "204";
    pub const ACTIVE: &str = "B0";
    pub const SUPPORTED_CAMERA_RECORDING_CONFIGURATION: &str = "205";
    pub const SUPPORTED_VIDEO_RECORDING_CONFIGURATION: &str = "206";
    pub const SUPPORTED_AUDIO_RECORDING_CONFIGURATION: &str = "207";
    pub const SELECTED_CAMERA_RECORDING_CONFIGURATION: &str = "209";
    pub const RECORDING_AUDIO_ACTIVE: &str = "226";

    pub const DATA_STREAM_TRANSPORT_MANAGEMENT: &str = "129";
    pub const SUPPORTED_DATA_STREAM_TRANSPORT_CONFIGURATION: &str = "130";
    pub const SETUP_DATA_STREAM_TRANSPORT: &str = "131";
    pub const VERSION: &str = "37";
}

/// What can start a recording.
pub const TRIGGER_MOTION: u8 = 0x01;
pub const TRIGGER_DOORBELL: u8 = 0x02;

/// Video kept from before the event, in milliseconds.
pub const PREBUFFER_MS: u32 = 4000;
/// Length of each piece of a recording, in milliseconds.
pub const FRAGMENT_MS: u32 = 4000;

const AAC_LC: u8 = 0;
const H264: u8 = 0;
const FRAGMENTED_MP4: u8 = 0;

/// Sample rates in the order of their protocol codes.
const SAMPLE_RATES: [u32; 6] = [8000, 16000, 24000, 32000, 44100, 48000];

fn supported_recording(triggers: u8) -> Value {
    let container = Tlv::new()
        .with(0x01, &[FRAGMENTED_MP4])
        .with(0x02, &Tlv::new().with(0x01, &FRAGMENT_MS.to_le_bytes()).encode());
    tlv_value(
        &Tlv::new()
            .with(0x01, &PREBUFFER_MS.to_le_bytes())
            .with(0x02, &(triggers as u64).to_le_bytes())
            .with(0x03, &container.encode()),
    )
}

/// H.264 at main and high profile, for the given `(width, height, frames
/// per second)` choices.
fn supported_video(resolutions: &[(u16, u16, u8)]) -> Value {
    let mut parameters = Tlv::new();
    for (i, profile) in [1u8, 2].iter().enumerate() {
        if i > 0 {
            separator(&mut parameters);
        }
        parameters.push(0x01, &[*profile]);
    }
    // Levels 3.1, 3.2 and 4.0.
    for (i, level) in [0u8, 1, 2].iter().enumerate() {
        if i > 0 {
            separator(&mut parameters);
        }
        parameters.push(0x02, &[*level]);
    }
    let mut codec = Tlv::new().with(0x01, &[H264]).with(0x02, &parameters.encode());
    for (i, (width, height, fps)) in resolutions.iter().enumerate() {
        if i > 0 {
            separator(&mut codec);
        }
        let attributes =
            Tlv::new().with(0x01, &width.to_le_bytes()).with(0x02, &height.to_le_bytes()).with(0x03, &[*fps]);
        codec.push(0x03, &attributes.encode());
    }
    tlv_value(&Tlv::new().with(0x01, &codec.encode()))
}

/// AAC-LC, mono, variable bitrate, at 16, 24, 32 or 48 kHz.
fn supported_audio() -> Value {
    let mut parameters = Tlv::new().with(0x01, &[1]).with(0x02, &[0]);
    for (i, rate) in [1u8, 2, 3, 5].iter().enumerate() {
        if i > 0 {
            separator(&mut parameters);
        }
        parameters.push(0x03, &[*rate]);
    }
    let codec = Tlv::new().with(0x01, &[AAC_LC]).with(0x02, &parameters.encode());
    tlv_value(&Tlv::new().with(0x01, &codec.encode()))
}

fn switch(kind: &'static str, on: bool) -> Characteristic {
    Characteristic {
        writable: true,
        ..Characteristic::sensor(kind, Format::Uint8, json!(u8::from(on))).range(0.0, 1.0, 1.0)
    }
}

/// The switches the Home app shows for a camera, in the order `event
/// snapshots, camera active, periodic snapshots`.
pub fn operating_mode_characteristics() -> Vec<Characteristic> {
    vec![
        switch(kind::EVENT_SNAPSHOTS_ACTIVE, true),
        switch(kind::HOMEKIT_CAMERA_ACTIVE, true),
        switch(kind::PERIODIC_SNAPSHOTS_ACTIVE, true),
    ]
}

/// Recording management, in the order `active, supported recording,
/// supported video, supported audio, selected configuration, audio active`.
pub fn recording_characteristics(resolutions: &[(u16, u16, u8)], triggers: u8) -> Vec<Characteristic> {
    let fixed = |kind, value| Characteristic::sensor(kind, Format::Tlv8, value);
    vec![
        switch(kind::ACTIVE, false),
        fixed(kind::SUPPORTED_CAMERA_RECORDING_CONFIGURATION, supported_recording(triggers)),
        fixed(kind::SUPPORTED_VIDEO_RECORDING_CONFIGURATION, supported_video(resolutions)),
        fixed(kind::SUPPORTED_AUDIO_RECORDING_CONFIGURATION, supported_audio()),
        Characteristic {
            writable: true,
            ..Characteristic::sensor(kind::SELECTED_CAMERA_RECORDING_CONFIGURATION, Format::Tlv8, json!(""))
        },
        switch(kind::RECORDING_AUDIO_ACTIVE, false),
    ]
}

/// Data stream transport, in the order `setup, supported, version`.
pub fn transport_characteristics() -> Vec<Characteristic> {
    // Transport type 0 is the HomeKit data stream over TCP.
    let supported = tlv_value(&Tlv::new().with(0x01, &Tlv::new().with(0x01, &[0]).encode()));
    vec![
        Characteristic {
            writable: true,
            write_response: true,
            ..Characteristic::constant(kind::SETUP_DATA_STREAM_TRANSPORT, Format::Tlv8, json!(""))
        },
        Characteristic::constant(kind::SUPPORTED_DATA_STREAM_TRANSPORT_CONFIGURATION, Format::Tlv8, supported),
        Characteristic::text(kind::VERSION, "1.0"),
    ]
}

/// What a home hub chose to have recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRecording {
    pub prebuffer_ms: u32,
    /// Bits from [`TRIGGER_MOTION`] and [`TRIGGER_DOORBELL`].
    pub triggers: u8,
    pub fragment_ms: u32,
    /// 0 baseline, 1 main, 2 high.
    pub profile: u8,
    /// 0 is level 3.1, 1 is 3.2, 2 is 4.0.
    pub level: u8,
    pub bitrate_kbps: u32,
    /// Longest allowed gap between keyframes, in milliseconds.
    pub keyframe_interval_ms: u32,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub audio_channels: u8,
    pub sample_rate_hz: u32,
    pub audio_bitrate_kbps: u32,
}

fn u32_le(tlv: &Tlv, ty: u8) -> Option<u32> {
    // Some fields are sent wider than four bytes; the low four suffice.
    Some(u32::from_le_bytes(tlv.get(ty)?.get(..4)?.try_into().ok()?))
}

pub fn parse_selected(value: &Value) -> Option<SelectedRecording> {
    let tlv = decode(value)?;
    let general = nested(&tlv, 0x01)?;
    let video = nested(&tlv, 0x02)?;
    let audio = nested(&tlv, 0x03)?;
    let container = nested(&general, 0x03)?;
    let video_parameters = nested(&video, 0x02)?;
    let video_attributes = nested(&video, 0x03)?;
    let audio_parameters = nested(&audio, 0x02)?;
    if container.get_u8(0x01)? != FRAGMENTED_MP4 || video.get_u8(0x01)? != H264 || audio.get_u8(0x01)? != AAC_LC {
        return None;
    }
    Some(SelectedRecording {
        prebuffer_ms: u32_le(&general, 0x01)?,
        triggers: *general.get(0x02)?.first()?,
        fragment_ms: u32_le(&nested(&container, 0x02)?, 0x01)?,
        profile: video_parameters.get_u8(0x01)?,
        level: video_parameters.get_u8(0x02)?,
        bitrate_kbps: u32_le(&video_parameters, 0x03)?,
        keyframe_interval_ms: u32_le(&video_parameters, 0x04)?,
        width: u16_le(&video_attributes, 0x01)?,
        height: u16_le(&video_attributes, 0x02)?,
        fps: video_attributes.get_u8(0x03)?,
        audio_channels: audio_parameters.get_u8(0x01)?,
        sample_rate_hz: *SAMPLE_RATES.get(audio_parameters.get_u8(0x03)? as usize)?,
        audio_bitrate_kbps: u32_le(&audio_parameters, 0x04)?,
    })
}

/// The controller's salt from a request to set up a data stream, if the
/// request is one this accessory can serve.
pub fn parse_transport_setup(value: &Value) -> Option<Vec<u8>> {
    let tlv = decode(value)?;
    // Command 0 starts a session; transport 0 is the HomeKit data stream.
    let salt = tlv.get(0x03)?;
    (tlv.get_u8(0x01)? == 0 && tlv.get_u8(0x02)? == 0 && salt.len() == 32).then(|| salt.to_vec())
}

/// The answer to a data stream setup: where to connect and this side's salt.
pub fn transport_response(port: u16, accessory_salt: &[u8; 32]) -> Value {
    tlv_value(
        &Tlv::new()
            .with(0x01, &[0])
            .with(0x02, &Tlv::new().with(0x01, &port.to_le_bytes()).encode())
            .with(0x03, accessory_salt),
    )
}

/// The answer when no more data streams can be set up right now.
pub fn transport_busy() -> Value {
    tlv_value(&Tlv::new().with(0x01, &[2]))
}

/// Builds the values a home hub would write, for tests of code that sits
/// on top of this module. Not part of the stable interface.
#[doc(hidden)]
pub mod test_support {
    use super::*;

    pub fn selected_value(width: u16, height: u16, fps: u8, kbps: u32, sample_rate_code: u8) -> Value {
        let container = Tlv::new()
            .with(0x01, &[FRAGMENTED_MP4])
            .with(0x02, &Tlv::new().with(0x01, &FRAGMENT_MS.to_le_bytes()).encode());
        let general = Tlv::new()
            .with(0x01, &PREBUFFER_MS.to_le_bytes())
            .with(0x02, &((TRIGGER_MOTION | TRIGGER_DOORBELL) as u64).to_le_bytes())
            .with(0x03, &container.encode());
        let video_parameters = Tlv::new()
            .with(0x01, &[2])
            .with(0x02, &[2])
            .with(0x03, &kbps.to_le_bytes())
            .with(0x04, &4000u32.to_le_bytes());
        let attributes =
            Tlv::new().with(0x01, &width.to_le_bytes()).with(0x02, &height.to_le_bytes()).with(0x03, &[fps]);
        let video = Tlv::new()
            .with(0x01, &[H264])
            .with(0x02, &video_parameters.encode())
            .with(0x03, &attributes.encode());
        let audio_parameters = Tlv::new()
            .with(0x01, &[1])
            .with(0x02, &[0])
            .with(0x03, &[sample_rate_code])
            .with(0x04, &24u32.to_le_bytes());
        let audio = Tlv::new().with(0x01, &[AAC_LC]).with(0x02, &audio_parameters.encode());
        tlv_value(&Tlv::new().with(0x01, &general.encode()).with(0x02, &video.encode()).with(0x03, &audio.encode()))
    }

    pub fn transport_setup_value(salt: &[u8]) -> Value {
        tlv_value(&Tlv::new().with(0x01, &[0]).with(0x02, &[0]).with(0x03, salt))
    }

    /// The port and salt from a transport response.
    pub fn transport_answer(value: &Value) -> Option<(u16, Vec<u8>)> {
        let tlv = decode(value)?;
        (tlv.get_u8(0x01)? == 0).then_some(())?;
        Some((u16_le(&nested(&tlv, 0x02)?, 0x01)?, tlv.get(0x03)?.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_a_hub_selects() {
        let selected = parse_selected(&test_support::selected_value(1920, 1080, 30, 2000, 2)).unwrap();
        assert_eq!(
            selected,
            SelectedRecording {
                prebuffer_ms: 4000,
                triggers: TRIGGER_MOTION | TRIGGER_DOORBELL,
                fragment_ms: 4000,
                profile: 2,
                level: 2,
                bitrate_kbps: 2000,
                keyframe_interval_ms: 4000,
                width: 1920,
                height: 1080,
                fps: 30,
                audio_channels: 1,
                sample_rate_hz: 24000,
                audio_bitrate_kbps: 24,
            }
        );
        assert!(parse_selected(&json!("")).is_none());
        assert!(parse_selected(&json!("not base64!")).is_none());
        // A sample rate code that does not exist.
        assert!(parse_selected(&test_support::selected_value(1920, 1080, 30, 2000, 9)).is_none());
    }

    #[test]
    fn offers_are_well_formed() {
        let general = decode(&supported_recording(TRIGGER_MOTION | TRIGGER_DOORBELL)).unwrap();
        assert_eq!(u32_le(&general, 0x01), Some(PREBUFFER_MS));
        assert_eq!(general.get(0x02), Some(&[3u8, 0, 0, 0, 0, 0, 0, 0][..]));
        let container = nested(&general, 0x03).unwrap();
        assert_eq!(u32_le(&nested(&container, 0x02).unwrap(), 0x01), Some(FRAGMENT_MS));

        let codec = nested(&decode(&supported_video(&[(1920, 1080, 30), (1280, 720, 30)])).unwrap(), 0x01).unwrap();
        let first = nested(&codec, 0x03).unwrap();
        assert_eq!((u16_le(&first, 0x01), u16_le(&first, 0x02), first.get_u8(0x03)), (Some(1920), Some(1080), Some(30)));

        let audio = nested(&decode(&supported_audio()).unwrap(), 0x01).unwrap();
        assert_eq!(audio.get_u8(0x01), Some(AAC_LC));

        assert_eq!(operating_mode_characteristics().len(), 3);
        let recording = recording_characteristics(&[(1280, 720, 30)], TRIGGER_MOTION);
        assert_eq!(recording.len(), 6);
        assert!(recording[4].writable && recording[4].notifies);
        let transport = transport_characteristics();
        assert!(transport[0].write_response && transport[0].writable);
    }

    #[test]
    fn transport_setup_round_trips_and_refuses_odd_requests() {
        assert_eq!(parse_transport_setup(&test_support::transport_setup_value(&[5; 32])), Some(vec![5; 32]));
        assert_eq!(parse_transport_setup(&test_support::transport_setup_value(&[5; 16])), None);
        assert_eq!(parse_transport_setup(&json!("")), None);
        let answer = transport_response(51234, &[8; 32]);
        assert_eq!(test_support::transport_answer(&answer), Some((51234, vec![8; 32])));
        assert_eq!(test_support::transport_answer(&transport_busy()), None);
    }
}
