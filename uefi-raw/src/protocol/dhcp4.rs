use crate::{guid, Char8, Guid, Status};
use core::ffi::c_void;
use core::ptr;

newtype_enum! {
    pub enum Event: i32 => {
      NULL                  = 0x00,
      DHCP4_SEND_DISCOVER   = 0x01,
      DHCP4_RCVD_OFFER      = 0x02,
      DHCP4_SELECT_OFFER    = 0x03,
      DHCP4_SEND_REQUEST    = 0x04,
      DHCP4_RCVD_ACK        = 0x05,
      DHCP4_RCVD_NAK        = 0x06,
      DHCP4_SEND_DECLINE    = 0x07,
      DHCP4_BOUND_COMPLETED = 0x08,
      DHCP4_ENTER_RENEWING  = 0x09,
      DHCP4_ENTER_REBINDING = 0x0a,
      DHCP4_ADDRESS_LOST    = 0x0b,
      DHCP4_FAIL            = 0x0c,
    }
}

newtype_enum! {
    #[derive(Default)]
    pub enum State: i32 => {
        DHCP4_STOPPED     = 0x0,
        DHCP4_INIT        = 0x1,
        DHCP4_SELECTING   = 0x2,
        DHCP4_REQUESTING  = 0x3,
        DHCP4_BOUND       = 0x4,
        DHCP4_RENEWING    = 0x5,
        DHCP4_REBINDING   = 0x6,
        DHCP4_INIT_REBOOT = 0x7,
        DHCP4_REBOOTING   = 0x8,
    }
}

#[repr(C, packed(1))]
pub struct Packet {
    pub size: u32,
    pub length: u32,
    pub op_code: u8,
    pub hw_type: u8,
    pub hw_addr_len: u8,
    pub hops: u8,
    pub xid: u32,
    pub seconds: u16,
    pub reserved: u16,
    pub client_addr: [u8; 4],
    pub your_addr: [u8; 4],
    pub server_addr: [u8; 4],
    pub gateway_addr: [u8; 4],
    pub client_hw_addr: [u8; 16],
    pub server_name: [Char8; 64],
    pub boot_file_name: [Char8; 128],
    pub magik: u32,
    pub option: [u8; 1],
}

#[repr(C, packed(1))]
pub struct PacketOption {
    pub op_code: u8,
    pub length: u8,
    pub data: [u8; 1],
}

#[derive(Debug)]
#[repr(C)]
pub struct ConfigData {
    pub discover_try_count: u32,
    pub discover_try_timeout: *mut u32,
    pub request_try_count: u32,
    pub request_try_timeout: *mut u32,
    pub client_address: [u8; 4],
    pub callback: Option<
        extern "efiapi" fn(
            this: *mut Dhcp4Protocol,
            context: *const c_void,
            current_state: State,
            dhcp4_event: Event,
            packet: *mut Packet,
            new_packet: *mut *mut Packet,
        ) -> Status,
    >,
    pub callback_context: *const c_void,
    pub option_count: u32,
    pub option_list: *mut *mut PacketOption,
}

impl Default for ConfigData {
    fn default() -> Self {
        let mut options: *mut PacketOption = ptr::null_mut();
        ConfigData {
            discover_try_count: 0,
            discover_try_timeout: ptr::null_mut(),
            request_try_count: 0,
            request_try_timeout: ptr::null_mut(),
            client_address: [0x00, 0x00, 0x00, 0x00],
            callback: None,
            callback_context: ptr::null(),
            option_count: 0,
            option_list: &mut options,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ModeData {
    pub state: State,
    pub config_data: ConfigData,
    pub client_address: [u8; 4],
    pub client_mac_address: [u8; 32],
    pub server_address: [u8; 4],
    pub router_address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub lease_time: u32,
    pub reply_packet: *mut Packet,
}

impl Default for ModeData {
    fn default() -> Self {
        ModeData {
            state: State::default(),
            config_data: ConfigData::default(),
            client_address: [0x00; 4],
            client_mac_address: [0x00; 32],
            server_address: [0x00; 4],
            router_address: [0x00; 4],
            subnet_mask: [0x00; 4],
            lease_time: 0,
            reply_packet: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct ListenPoint {
    pub listen_address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub listen_port: u16,
}

#[repr(C)]
pub struct TransmitReceiveToken {
    pub status: Status,
    pub completion_event: Event,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
    pub gateway_address: [u8; 4],
    pub listen_point_count: u32,
    pub listen_points: *mut ListenPoint,
    pub timeout_value: u32,
    pub packet: *mut Packet,
    pub response_count: u32,
    pub response_list: *mut Packet,
}

#[repr(C)]
pub struct Dhcp4Protocol {
    pub get_mode_data: unsafe extern "efiapi" fn(this: &Self, mode_data: *mut ModeData) -> Status,
    pub configure: unsafe extern "efiapi" fn(this: &Self, cfg_data: *mut ConfigData) -> Status,
    pub start: extern "efiapi" fn(this: &Self, completion_event: Event) -> Status,
    pub renew_rebind: unsafe extern "efiapi" fn(
        this: &Self,
        rebind_request: bool,
        completion_event: Event,
    ) -> Status,
    pub release: extern "efiapi" fn(this: &Self) -> Status,
    pub stop: extern "efiapi" fn(this: &Self) -> Status,
    pub build: unsafe extern "efiapi" fn(
        this: &Self,
        seed_packet: *mut Packet,
        delete_count: u32,
        delete_list: *mut u8,
        append_count: u32,
        append_list: *mut PacketOption,
        new_packet: *mut *mut Packet,
    ) -> Status,
    pub transmit_receive:
        unsafe extern "efiapi" fn(this: &Self, token: *mut TransmitReceiveToken) -> Status,
    pub parse: unsafe extern "efiapi" fn(
        this: &Self,
        packet: *mut Packet,
        option_count: *mut u32,
        packet_option_list: *mut PacketOption,
    ) -> Status,
}

impl Dhcp4Protocol {
    pub const GUID: Guid = guid!("8a219718-4ef5-4761-91c8-c0f04bda9e56");
    pub const BINDING_GUID: Guid = guid!("9d9a39d8-bd42-4a73-a4d5-8ee94be11380");
}
