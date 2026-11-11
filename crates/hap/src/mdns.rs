//! Bonjour advertisement of the bridge as a `_hap._tcp` service.
//!
//! On macOS this registers with the system's own Bonjour daemon. Running a
//! second mDNS responder next to it does not work reliably: records ended up
//! visible on the loopback interface only, so controllers could see the
//! bridge by name but never resolve its address. The system daemon also
//! withdraws the records by itself if this process dies.
//!
//! Other platforms use a bundled responder.

/// HomeKit accessory category: bridge.
const CATEGORY_BRIDGE: &str = "2";

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

pub struct Advertiser {
    backend: backend::Backend,
    model: String,
    device_id: String,
    setup_hash: String,
}

impl Advertiser {
    pub fn new(
        name: &str,
        model: &str,
        device_id: &str,
        setup_hash: &str,
        port: u16,
    ) -> Result<Self, Error> {
        Ok(Self {
            backend: backend::Backend::new(name, device_id, port)?,
            model: model.to_owned(),
            device_id: device_id.to_owned(),
            setup_hash: setup_hash.to_owned(),
        })
    }

    /// Publishes or refreshes the advertisement. Controllers watch `sf` to
    /// learn whether the bridge is available for pairing and `c#` to learn
    /// that the accessory database changed.
    pub fn publish(&mut self, config_number: u32, paired: bool) -> Result<(), Error> {
        let config_number = config_number.to_string();
        self.backend.publish(&[
            ("c#", config_number.as_str()),
            ("ff", "0"),
            ("id", self.device_id.as_str()),
            ("md", self.model.as_str()),
            ("pv", "1.1"),
            ("s#", "1"),
            ("sf", if paired { "0" } else { "1" }),
            ("ci", CATEGORY_BRIDGE),
            ("sh", self.setup_hash.as_str()),
        ])
    }
}

/// Encodes TXT properties as DNS-SD wants them: length-prefixed `key=value`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn encode_txt(properties: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in properties {
        let entry = format!("{key}={value}");
        // HomeKit values are short; anything over 255 bytes is a bug upstream.
        let len = entry.len().min(255);
        out.push(len as u8);
        out.extend_from_slice(&entry.as_bytes()[..len]);
    }
    out
}

#[cfg(target_os = "macos")]
mod backend {
    use std::ffi::{c_char, c_void, CString};
    use std::ptr;

    use super::{encode_txt, Error};

    type ServiceRef = *mut c_void;

    // From <dns_sd.h>, part of libSystem.
    extern "C" {
        fn DNSServiceRegister(
            sd_ref: *mut ServiceRef,
            flags: u32,
            interface_index: u32,
            name: *const c_char,
            regtype: *const c_char,
            domain: *const c_char,
            host: *const c_char,
            port_network_order: u16,
            txt_len: u16,
            txt_record: *const c_void,
            callback: *const c_void,
            context: *mut c_void,
        ) -> i32;
        fn DNSServiceUpdateRecord(
            sd_ref: ServiceRef,
            record_ref: *mut c_void,
            flags: u32,
            rdata_len: u16,
            rdata: *const c_void,
            ttl: u32,
        ) -> i32;
        fn DNSServiceRefDeallocate(sd_ref: ServiceRef);
    }

    pub struct Backend {
        name: CString,
        port: u16,
        /// Null until the first publish.
        service: ServiceRef,
    }

    // The handle is only touched through `&mut self`, so never concurrently.
    unsafe impl Send for Backend {}

    impl Backend {
        pub fn new(name: &str, _device_id: &str, port: u16) -> Result<Self, Error> {
            let name = CString::new(name).map_err(|_| Error("service name contains a NUL byte".into()))?;
            Ok(Self { name, port, service: ptr::null_mut() })
        }

        pub fn publish(&mut self, properties: &[(&str, &str)]) -> Result<(), Error> {
            let txt = encode_txt(properties);
            let code = if self.service.is_null() {
                // SAFETY: every pointer is valid for the duration of the call
                // and the daemon copies what it needs. A null callback and a
                // null host ask the system to manage naming conflicts and to
                // advertise this machine's own hostname and addresses. Zero
                // for the interface means all network interfaces.
                unsafe {
                    DNSServiceRegister(
                        &mut self.service,
                        0,
                        0,
                        self.name.as_ptr(),
                        c"_hap._tcp".as_ptr(),
                        ptr::null(),
                        ptr::null(),
                        self.port.to_be(),
                        txt.len() as u16,
                        txt.as_ptr().cast(),
                        ptr::null(),
                        ptr::null_mut(),
                    )
                }
            } else {
                // SAFETY: `service` is a live registration; a null record
                // reference selects its primary TXT record.
                unsafe {
                    DNSServiceUpdateRecord(
                        self.service,
                        ptr::null_mut(),
                        0,
                        txt.len() as u16,
                        txt.as_ptr().cast(),
                        0,
                    )
                }
            };
            if code == 0 {
                Ok(())
            } else {
                Err(Error(format!("system Bonjour service returned error {code}")))
            }
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            if !self.service.is_null() {
                // SAFETY: the handle came from DNSServiceRegister and is not
                // used again. Deallocating withdraws the advertisement.
                unsafe { DNSServiceRefDeallocate(self.service) };
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod backend {
    use mdns_sd::{ServiceDaemon, ServiceInfo};

    use super::Error;

    pub struct Backend {
        daemon: ServiceDaemon,
        name: String,
        host: String,
        port: u16,
    }

    impl Backend {
        pub fn new(name: &str, device_id: &str, port: u16) -> Result<Self, Error> {
            Ok(Self {
                daemon: ServiceDaemon::new().map_err(|e| Error(e.to_string()))?,
                name: name.to_owned(),
                host: format!("harbormaster-{}.local.", device_id.replace(':', "").to_lowercase()),
                port,
            })
        }

        pub fn publish(&mut self, properties: &[(&str, &str)]) -> Result<(), Error> {
            ServiceInfo::new("_hap._tcp.local.", &self.name, &self.host, (), self.port, properties)
                .map(ServiceInfo::enable_addr_auto)
                .and_then(|info| self.daemon.register(info))
                .map_err(|e| Error(e.to_string()))
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            // Best effort goodbye so controllers notice the bridge leaving.
            let _ = self.daemon.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_entries_are_length_prefixed() {
        assert_eq!(encode_txt(&[("sf", "1"), ("pv", "1.1")]), b"\x04sf=1\x06pv=1.1");
    }
}
