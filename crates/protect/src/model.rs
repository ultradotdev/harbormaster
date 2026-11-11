//! The parts of UniFi Protect's bootstrap document Harbormaster uses.
//!
//! This is a private API that changes between Protect releases, so every
//! field is optional or defaulted and unknown fields are ignored.

use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Bootstrap {
    pub nvr: Nvr,
    pub cameras: Vec<Camera>,
    pub lights: Vec<Device>,
    pub sensors: Vec<Device>,
    pub chimes: Vec<Device>,
    /// Where the realtime update stream should resume from.
    pub last_update_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Nvr {
    pub id: String,
    pub mac: String,
    pub name: Option<String>,
    pub version: String,
    /// Hardware model, for example `UNVR`.
    #[serde(rename = "type")]
    pub model: String,
}

/// Fields common to every adopted device.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Device {
    pub id: String,
    pub mac: String,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub model: String,
    pub market_name: Option<String>,
    /// `CONNECTED`, `DISCONNECTED` and similar.
    pub state: String,
    pub firmware_version: Option<String>,
}

impl Device {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().or(self.market_name.as_deref()).unwrap_or(&self.model)
    }

    pub fn is_connected(&self) -> bool {
        self.state == "CONNECTED"
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Camera {
    #[serde(flatten)]
    pub device: Device,
    /// `h264` or `h265`.
    pub video_codec: Option<String>,
    pub channels: Vec<Channel>,
    pub feature_flags: FeatureFlags,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Channel {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate: u32,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FeatureFlags {
    pub is_doorbell: bool,
    pub has_smart_detect: bool,
    pub smart_detect_types: Vec<String>,
    pub has_speaker: bool,
    pub has_mic: bool,
    pub has_chime: bool,
    pub has_package_camera: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerates_missing_and_unknown_fields() {
        let json = r#"{
            "nvr": {"id": "n1", "mac": "AABB", "name": "Shed", "version": "6.2.1", "type": "UNVR", "brandNew": 1},
            "cameras": [
                {"id": "c1", "mac": "0011", "name": "Front Door", "type": "UVC G4 Doorbell Pro",
                 "state": "CONNECTED", "videoCodec": "h264",
                 "channels": [{"id": 0, "name": "High", "enabled": true, "width": 1600, "height": 1200, "fps": 30, "bitrate": 6000000}],
                 "featureFlags": {"isDoorbell": true, "smartDetectTypes": ["person", "package"], "futureFlag": {}}},
                {"id": "c2", "mac": "0022", "name": null, "type": "UVC G5 Bullet", "marketName": "G5 Bullet", "state": "DISCONNECTED"}
            ],
            "lastUpdateId": "abc",
            "somethingNew": [1, 2, 3]
        }"#;
        let bootstrap: Bootstrap = serde_json::from_str(json).unwrap();
        assert_eq!((bootstrap.nvr.model.as_str(), bootstrap.nvr.version.as_str()), ("UNVR", "6.2.1"));
        let [door, bullet] = bootstrap.cameras.as_slice() else { panic!("two cameras") };
        assert_eq!(door.device.display_name(), "Front Door");
        assert!(door.device.is_connected() && door.feature_flags.is_doorbell);
        assert_eq!(door.channels[0].width, 1600);
        assert_eq!(door.feature_flags.smart_detect_types, ["person", "package"]);
        assert_eq!(bullet.device.display_name(), "G5 Bullet");
        assert!(!bullet.device.is_connected() && bullet.channels.is_empty());
        assert!(bootstrap.lights.is_empty());
        assert_eq!(bootstrap.last_update_id.as_deref(), Some("abc"));
    }
}
