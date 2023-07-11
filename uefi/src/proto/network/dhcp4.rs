//! `DHCPv4` protocol.

use crate::proto::unsafe_protocol;
use crate::{Handle, Result, Status, StatusExt};
use core::ptr;
use uefi_raw::protocol::dhcp4::{ConfigData, Dhcp4Protocol, Event, ModeData};

/// DHCPv4 Service Binding Protocol
#[repr(transparent)]
#[unsafe_protocol(Dhcp4Protocol::BINDING_GUID)]
pub struct Dhcp4ServiceBinding(uefi_raw::protocol::ServiceBinding);

impl Dhcp4ServiceBinding {
    /// Creates a child handle and installs a protocol.
    pub fn create_child(self: &mut Self) -> Result<Handle> {
        let mut child_handle = ptr::null_mut() as uefi_raw::Handle;
        unsafe {
            (self.0.create_child)(&mut self.0, &mut child_handle)
                .to_result_with_val(|| Handle::from_ptr(child_handle).unwrap())
        }
    }

    /// Destroys a child handle with a protocol installed on it.
    pub fn destroy_child(self: &mut Self, child_handle: Handle) -> Status {
        unsafe { (self.0.destroy_child)(&mut self.0, child_handle.as_ptr()) }
    }
}

/// DHCPv4 Protocol
#[repr(transparent)]
#[unsafe_protocol(Dhcp4Protocol::GUID)]
pub struct Dhcp4(Dhcp4Protocol);

impl Dhcp4 {
    /// Try completing a DHCPv4 Discover/Offer/Request/Acknowledge sequence.
    pub fn bind(&mut self) -> Result {
        let mut config = ConfigData::default();
        unsafe {
            (self.0.configure)(&mut self.0, &mut config).to_result()?;
            (self.0.start)(&mut self.0, Event::NULL).to_result()
        }
    }

    /// Get the bound IP, returning 0.0.0.0 if no IP is currently bound.
    pub fn bound_ip(&mut self) -> Result<[u8; 4]> {
        self.mode_data().map(|d| d.client_address)
    }

    /// Get the Mode Data for the DHCP client
    fn mode_data(&mut self) -> Result<ModeData> {
        let mut data = ModeData::default();
        unsafe {
            (self.0.get_mode_data)(&mut self.0, &mut data)
                .to_result()
                .map(|_| data)
        }
    }
}
