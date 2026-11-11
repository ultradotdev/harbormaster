//! Bonjour advertisement of the bridge as a `_hap._tcp` service.

use mdns_sd::{ServiceDaemon, ServiceInfo};

const SERVICE_TYPE: &str = "_hap._tcp.local.";
/// HomeKit accessory category: bridge.
const CATEGORY_BRIDGE: &str = "2";

pub struct Advertiser {
    daemon: ServiceDaemon,
    name: String,
    model: String,
    device_id: String,
    setup_hash: String,
    port: u16,
}

impl Advertiser {
    pub fn new(
        name: &str,
        model: &str,
        device_id: &str,
        setup_hash: &str,
        port: u16,
    ) -> Result<Self, mdns_sd::Error> {
        Ok(Self {
            daemon: ServiceDaemon::new()?,
            name: name.to_owned(),
            model: model.to_owned(),
            device_id: device_id.to_owned(),
            setup_hash: setup_hash.to_owned(),
            port,
        })
    }

    /// Publishes or refreshes the advertisement. Controllers watch `sf` to
    /// learn whether the bridge is available for pairing and `c#` to learn
    /// that the accessory database changed.
    pub fn publish(&self, config_number: u32, paired: bool) -> Result<(), mdns_sd::Error> {
        let config_number = config_number.to_string();
        let properties = [
            ("c#", config_number.as_str()),
            ("ff", "0"),
            ("id", self.device_id.as_str()),
            ("md", self.model.as_str()),
            ("pv", "1.1"),
            ("s#", "1"),
            ("sf", if paired { "0" } else { "1" }),
            ("ci", CATEGORY_BRIDGE),
            ("sh", self.setup_hash.as_str()),
        ];
        let host = format!("harbormaster-{}.local.", self.device_id.replace(':', "").to_lowercase());
        let info = ServiceInfo::new(SERVICE_TYPE, &self.name, &host, (), self.port, &properties[..])?
            .enable_addr_auto();
        self.daemon.register(info)
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        // Best effort goodbye so controllers notice the bridge leaving.
        let _ = self.daemon.shutdown();
    }
}
