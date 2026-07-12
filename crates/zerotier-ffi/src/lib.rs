//! C ABI bindings for the ManyTier node engine.
//!
//! Builds as a `cdylib` for embedding the node in non-Rust hosts. This is
//! the only crate in the workspace permitted to use `unsafe` (required for
//! the C ABI surface).

use core::ptr;
use core::slice;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;

use zerotier_crypto::identity::Identity;
use zerotier_node::node::{Node, NodeAction};

/// Status returned by every fallible C ABI entry point.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManyTierFfiStatus {
    Ok = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    InvalidIdentity = 3,
    MissingIdentitySecret = 4,
    InvalidPlanet = 5,
    InvalidIndex = 6,
    InvalidSocketAddress = 7,
}

/// Pending action variant exposed across the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManyTierFfiActionKind {
    Unknown = 0,
    SendTo = 1,
    WhoisNeeded = 2,
    FrameReceived = 3,
    LocalReply = 4,
    NetworkConfigured = 5,
    NetworkConfigRequested = 6,
    UserMessageReceived = 7,
    RemoteTraceReceived = 8,
    PathNegotiationReceived = 9,
}

/// Socket address encoded for C callers.
///
/// `family` is 4 for IPv4 and 6 for IPv6. `address` stores IPv4 octets in the
/// first four bytes for IPv4 and all sixteen octets for IPv6. `port` is host
/// endian.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManyTierFfiSocketAddress {
    pub family: u8,
    pub address: [u8; 16],
    pub port: u16,
}

impl Default for ManyTierFfiSocketAddress {
    fn default() -> Self {
        Self {
            family: 0,
            address: [0; 16],
            port: 0,
        }
    }
}

/// Borrowed view of a pending node action.
///
/// Payload pointers are owned by the node handle and stay valid until the next
/// action-producing call, [`manytier_node_clear_actions`], or
/// [`manytier_node_free`]. For `WhoisNeeded`, `data_ptr` is a flat sequence of
/// `address_count` five-byte ZeroTier addresses.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ManyTierFfiActionView {
    pub kind: ManyTierFfiActionKind,
    pub socket_address: ManyTierFfiSocketAddress,
    pub data_ptr: *const u8,
    pub data_len: usize,
    pub address_count: usize,
    pub network_id: u64,
    pub packet_id: u64,
    pub type_id: u64,
    pub zt_address: [u8; 5],
    pub src_mac: [u8; 6],
    pub dest_mac: [u8; 6],
    pub ethertype: u16,
    pub utility: i16,
}

impl Default for ManyTierFfiActionView {
    fn default() -> Self {
        Self {
            kind: ManyTierFfiActionKind::Unknown,
            socket_address: ManyTierFfiSocketAddress::default(),
            data_ptr: ptr::null(),
            data_len: 0,
            address_count: 0,
            network_id: 0,
            packet_id: 0,
            type_id: 0,
            zt_address: [0; 5],
            src_mac: [0; 6],
            dest_mac: [0; 6],
            ethertype: 0,
            utility: 0,
        }
    }
}

/// Opaque node handle owned by foreign callers.
pub struct ManyTierNode {
    node: Node,
    actions: Vec<NodeAction>,
}

/// Create a node from an `identity.secret` string and planet/moon world bytes.
///
/// The caller owns the returned handle and must release it with
/// [`manytier_node_free`]. `identity_ptr` is UTF-8 and may omit a trailing NUL;
/// `planet_ptr` points to raw world bytes.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_new(
    identity_ptr: *const u8,
    identity_len: usize,
    planet_ptr: *const u8,
    planet_len: usize,
    initial_packet_id: u64,
    out_node: *mut *mut ManyTierNode,
) -> ManyTierFfiStatus {
    if out_node.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }

    let identity_bytes = match unsafe_slice(identity_ptr, identity_len) {
        Some(bytes) => bytes,
        None => return ManyTierFfiStatus::NullPointer,
    };
    let planet_bytes = match unsafe_slice(planet_ptr, planet_len) {
        Some(bytes) => bytes,
        None => return ManyTierFfiStatus::NullPointer,
    };

    let identity_str = match str::from_utf8(identity_bytes) {
        Ok(value) => value,
        Err(_) => return ManyTierFfiStatus::InvalidUtf8,
    };
    let identity = match Identity::parse(identity_str) {
        Ok(value) => value,
        Err(_) => return ManyTierFfiStatus::InvalidIdentity,
    };
    if identity.secret.is_none() {
        return ManyTierFfiStatus::MissingIdentitySecret;
    }

    let node = match Node::new(identity, planet_bytes, initial_packet_id) {
        Ok(value) => value,
        Err(_) => return ManyTierFfiStatus::InvalidPlanet,
    };
    let handle = Box::new(ManyTierNode {
        node,
        actions: Vec::new(),
    });
    unsafe {
        *out_node = Box::into_raw(handle);
    }
    ManyTierFfiStatus::Ok
}

/// Free a node handle returned by [`manytier_node_new`].
#[no_mangle]
pub unsafe extern "C" fn manytier_node_free(node: *mut ManyTierNode) {
    if !node.is_null() {
        unsafe {
            drop(Box::from_raw(node));
        }
    }
}

/// Copy the node's 5-byte ZeroTier address into `out_address`.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_address(
    node: *const ManyTierNode,
    out_address: *mut u8,
) -> ManyTierFfiStatus {
    if node.is_null() || out_address.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }
    let address = unsafe { &(*node).node.identity.address };
    unsafe {
        ptr::copy_nonoverlapping(address.as_bytes().as_ptr(), out_address, 5);
    }
    ManyTierFfiStatus::Ok
}

/// Generate initial HELLO actions and store them on the handle.
///
/// This first FFI slice exposes only the action count. Later slices should add
/// action marshalling so hosts can send packets, satisfy WHOIS requests, and
/// deliver virtual-network frames.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_bootstrap(
    node: *mut ManyTierNode,
    now_ms: u64,
    out_action_count: *mut usize,
) -> ManyTierFfiStatus {
    if node.is_null() || out_action_count.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }
    let handle = unsafe { &mut *node };
    handle.actions = handle.node.bootstrap(now_ms);
    unsafe {
        *out_action_count = handle.actions.len();
    }
    ManyTierFfiStatus::Ok
}

/// Process timer-driven node maintenance and store the resulting actions.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_tick(
    node: *mut ManyTierNode,
    now_ms: u64,
    out_action_count: *mut usize,
) -> ManyTierFfiStatus {
    if node.is_null() || out_action_count.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }
    let handle = unsafe { &mut *node };
    handle.actions = handle.node.tick(now_ms);
    unsafe {
        *out_action_count = handle.actions.len();
    }
    ManyTierFfiStatus::Ok
}

/// Process a received physical packet and store the resulting actions.
///
/// The packet bytes are copied before processing because the Rust node may
/// mutate the packet during decryption/decompression.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_receive_packet(
    node: *mut ManyTierNode,
    packet_ptr: *const u8,
    packet_len: usize,
    from: ManyTierFfiSocketAddress,
    now_ms: u64,
    out_action_count: *mut usize,
) -> ManyTierFfiStatus {
    if node.is_null() || out_action_count.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }
    let packet = match unsafe_slice(packet_ptr, packet_len) {
        Some(packet) => packet,
        None => return ManyTierFfiStatus::NullPointer,
    };
    let from = match socket_address_from_ffi(from) {
        Some(address) => address,
        None => return ManyTierFfiStatus::InvalidSocketAddress,
    };
    let handle = unsafe { &mut *node };
    let mut packet = packet.to_vec();
    handle.actions = handle.node.receive_packet(&mut packet, from, now_ms);
    unsafe {
        *out_action_count = handle.actions.len();
    }
    ManyTierFfiStatus::Ok
}

/// Return the number of actions currently stored on the handle.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_action_count(
    node: *const ManyTierNode,
    out_action_count: *mut usize,
) -> ManyTierFfiStatus {
    if node.is_null() || out_action_count.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }
    unsafe {
        *out_action_count = (*node).actions.len();
    }
    ManyTierFfiStatus::Ok
}

/// Copy a borrowed view of the pending action at `index` into `out_action`.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_action_view(
    node: *const ManyTierNode,
    index: usize,
    out_action: *mut ManyTierFfiActionView,
) -> ManyTierFfiStatus {
    if node.is_null() || out_action.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }
    let handle = unsafe { &*node };
    let Some(action) = handle.actions.get(index) else {
        return ManyTierFfiStatus::InvalidIndex;
    };
    unsafe {
        *out_action = action_view(action);
    }
    ManyTierFfiStatus::Ok
}

/// Clear pending actions stored by the last bootstrap/tick/receive call.
#[no_mangle]
pub unsafe extern "C" fn manytier_node_clear_actions(node: *mut ManyTierNode) -> ManyTierFfiStatus {
    if node.is_null() {
        return ManyTierFfiStatus::NullPointer;
    }
    unsafe {
        (*node).actions.clear();
    }
    ManyTierFfiStatus::Ok
}

fn unsafe_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

fn action_view(action: &NodeAction) -> ManyTierFfiActionView {
    match action {
        NodeAction::SendTo { data, address } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::SendTo,
            socket_address: socket_address_to_ffi(*address),
            data_ptr: data.as_ptr(),
            data_len: data.len(),
            ..ManyTierFfiActionView::default()
        },
        NodeAction::WhoisNeeded { addresses } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::WhoisNeeded,
            data_ptr: addresses.as_ptr().cast::<u8>(),
            data_len: addresses.len() * 5,
            address_count: addresses.len(),
            ..ManyTierFfiActionView::default()
        },
        NodeAction::FrameReceived {
            network_id,
            src_mac,
            dest_mac,
            ethertype,
            payload,
        } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::FrameReceived,
            data_ptr: payload.as_ptr(),
            data_len: payload.len(),
            network_id: *network_id,
            src_mac: *src_mac,
            dest_mac: *dest_mac,
            ethertype: *ethertype,
            ..ManyTierFfiActionView::default()
        },
        NodeAction::LocalReply {
            network_id,
            ethertype,
            payload,
        } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::LocalReply,
            data_ptr: payload.as_ptr(),
            data_len: payload.len(),
            network_id: *network_id,
            ethertype: *ethertype,
            ..ManyTierFfiActionView::default()
        },
        NodeAction::NetworkConfigured {
            network_id,
            dict_data,
        } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::NetworkConfigured,
            data_ptr: dict_data.as_ptr(),
            data_len: dict_data.len(),
            network_id: *network_id,
            ..ManyTierFfiActionView::default()
        },
        NodeAction::NetworkConfigRequested {
            requester_address,
            network_id,
            dict_data,
            from,
            packet_id,
        } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::NetworkConfigRequested,
            socket_address: socket_address_to_ffi(*from),
            data_ptr: dict_data.as_ptr(),
            data_len: dict_data.len(),
            network_id: *network_id,
            packet_id: *packet_id,
            zt_address: *requester_address,
            ..ManyTierFfiActionView::default()
        },
        NodeAction::UserMessageReceived {
            origin,
            type_id,
            data,
        } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::UserMessageReceived,
            data_ptr: data.as_ptr(),
            data_len: data.len(),
            type_id: *type_id,
            zt_address: *origin,
            ..ManyTierFfiActionView::default()
        },
        NodeAction::RemoteTraceReceived { origin, data } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::RemoteTraceReceived,
            data_ptr: data.as_ptr(),
            data_len: data.len(),
            zt_address: *origin,
            ..ManyTierFfiActionView::default()
        },
        NodeAction::PathNegotiationReceived { origin, utility } => ManyTierFfiActionView {
            kind: ManyTierFfiActionKind::PathNegotiationReceived,
            zt_address: *origin,
            utility: *utility,
            ..ManyTierFfiActionView::default()
        },
    }
}

fn socket_address_to_ffi(address: SocketAddr) -> ManyTierFfiSocketAddress {
    match address {
        SocketAddr::V4(address) => {
            let mut out = ManyTierFfiSocketAddress {
                family: 4,
                port: address.port(),
                ..ManyTierFfiSocketAddress::default()
            };
            out.address[..4].copy_from_slice(&address.ip().octets());
            out
        }
        SocketAddr::V6(address) => ManyTierFfiSocketAddress {
            family: 6,
            address: address.ip().octets(),
            port: address.port(),
        },
    }
}

fn socket_address_from_ffi(address: ManyTierFfiSocketAddress) -> Option<SocketAddr> {
    match address.family {
        4 => Some(SocketAddr::from((
            Ipv4Addr::new(
                address.address[0],
                address.address[1],
                address.address[2],
                address.address[3],
            ),
            address.port,
        ))),
        6 => Some(SocketAddr::from((
            Ipv6Addr::from(address.address),
            address.port,
        ))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_protocol::world::DEFAULT_PLANET;

    const CLIENT_SECRET: &str = "faa900da4a:0:fd0c3dc3ff88ff7cbac1df44f638aa22e69a13d4f9cc90f9fb15c882c4f13e732af074384f2b44a3fc211ea490259bcf1d6cd3b6aefc19a92accef90f73ca9ce:254ad73a7b1478e7283e6ab40a81b017dd2c7296b53a6f5348b30a33f890bef1e015930d2b36979bb57bd0f83ccb01c21dfdadc446d641c49a0f9c478905082a";

    #[test]
    fn node_handle_lifecycle_bootstraps_actions() {
        let mut node = ptr::null_mut();
        let status = unsafe {
            manytier_node_new(
                CLIENT_SECRET.as_ptr(),
                CLIENT_SECRET.len(),
                DEFAULT_PLANET.as_ptr(),
                DEFAULT_PLANET.len(),
                1,
                &mut node,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert!(!node.is_null());

        let mut address = [0u8; 5];
        let status = unsafe { manytier_node_address(node, address.as_mut_ptr()) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(address, [0xfa, 0xa9, 0x00, 0xda, 0x4a]);

        let mut action_count = 0usize;
        let status = unsafe { manytier_node_bootstrap(node, 1000, &mut action_count) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert!(action_count > 0, "bootstrap should emit root HELLO actions");

        let mut first_action = ManyTierFfiActionView::default();
        let status = unsafe { manytier_node_action_view(node, 0, &mut first_action) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(first_action.kind, ManyTierFfiActionKind::SendTo);
        assert!(!first_action.data_ptr.is_null());
        assert!(first_action.data_len > 0);
        assert!(matches!(first_action.socket_address.family, 4 | 6));
        assert!(first_action.socket_address.port > 0);

        let mut stored_count = 0usize;
        let status = unsafe { manytier_node_action_count(node, &mut stored_count) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(stored_count, action_count);

        let status = unsafe { manytier_node_clear_actions(node) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        let status = unsafe { manytier_node_action_count(node, &mut stored_count) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(stored_count, 0);

        let status = unsafe { manytier_node_action_view(node, 0, &mut first_action) };
        assert_eq!(status, ManyTierFfiStatus::InvalidIndex);

        unsafe { manytier_node_free(node) };
    }

    #[test]
    fn tick_and_receive_packet_store_action_counts() {
        let node = new_test_node();

        let mut action_count = usize::MAX;
        let status = unsafe { manytier_node_tick(node, 10_000, &mut action_count) };
        assert_eq!(status, ManyTierFfiStatus::Ok);

        let packet = [0u8; 8];
        let from = ManyTierFfiSocketAddress {
            family: 4,
            address: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 9993,
        };
        let status = unsafe {
            manytier_node_receive_packet(
                node,
                packet.as_ptr(),
                packet.len(),
                from,
                11_000,
                &mut action_count,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(action_count, 0);

        let bad_from = ManyTierFfiSocketAddress {
            family: 9,
            ..ManyTierFfiSocketAddress::default()
        };
        let status = unsafe {
            manytier_node_receive_packet(
                node,
                packet.as_ptr(),
                packet.len(),
                bad_from,
                11_000,
                &mut action_count,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::InvalidSocketAddress);

        unsafe { manytier_node_free(node) };
    }

    #[test]
    fn action_view_marshals_representative_variants() {
        let node = new_test_node();
        let handle = unsafe { &mut *node };
        handle.actions = vec![
            NodeAction::WhoisNeeded {
                addresses: vec![[1, 2, 3, 4, 5], [6, 7, 8, 9, 10]],
            },
            NodeAction::FrameReceived {
                network_id: 0x1234,
                src_mac: [1, 2, 3, 4, 5, 6],
                dest_mac: [6, 5, 4, 3, 2, 1],
                ethertype: 0x0800,
                payload: vec![0xaa, 0xbb],
            },
            NodeAction::NetworkConfigRequested {
                requester_address: [0xfa, 0xa9, 0, 0xda, 0x4a],
                network_id: 0x1122,
                dict_data: vec![0x10, 0x20, 0x30],
                from: "192.0.2.44:9993".parse().unwrap(),
                packet_id: 77,
            },
            NodeAction::UserMessageReceived {
                origin: [9, 8, 7, 6, 5],
                type_id: 42,
                data: vec![1, 2, 3],
            },
            NodeAction::RemoteTraceReceived {
                origin: [5, 4, 3, 2, 1],
                data: vec![4, 5],
            },
            NodeAction::PathNegotiationReceived {
                origin: [1, 1, 2, 2, 3],
                utility: -12,
            },
        ];

        let mut view = ManyTierFfiActionView::default();
        let status = unsafe { manytier_node_action_view(node, 0, &mut view) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(view.kind, ManyTierFfiActionKind::WhoisNeeded);
        assert_eq!(view.address_count, 2);
        assert_eq!(view.data_len, 10);
        assert_eq!(
            unsafe { slice::from_raw_parts(view.data_ptr, view.data_len) }[0..5],
            [1, 2, 3, 4, 5]
        );

        let status = unsafe { manytier_node_action_view(node, 1, &mut view) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(view.kind, ManyTierFfiActionKind::FrameReceived);
        assert_eq!(view.network_id, 0x1234);
        assert_eq!(view.src_mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(view.dest_mac, [6, 5, 4, 3, 2, 1]);
        assert_eq!(view.ethertype, 0x0800);
        assert_eq!(
            unsafe { slice::from_raw_parts(view.data_ptr, view.data_len) },
            [0xaa, 0xbb]
        );

        let status = unsafe { manytier_node_action_view(node, 2, &mut view) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(view.kind, ManyTierFfiActionKind::NetworkConfigRequested);
        assert_eq!(view.network_id, 0x1122);
        assert_eq!(view.packet_id, 77);
        assert_eq!(view.zt_address, [0xfa, 0xa9, 0, 0xda, 0x4a]);
        assert_eq!(view.socket_address.family, 4);
        assert_eq!(&view.socket_address.address[..4], &[192, 0, 2, 44]);
        assert_eq!(view.socket_address.port, 9993);

        let status = unsafe { manytier_node_action_view(node, 3, &mut view) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(view.kind, ManyTierFfiActionKind::UserMessageReceived);
        assert_eq!(view.type_id, 42);
        assert_eq!(view.zt_address, [9, 8, 7, 6, 5]);

        let status = unsafe { manytier_node_action_view(node, 4, &mut view) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(view.kind, ManyTierFfiActionKind::RemoteTraceReceived);
        assert_eq!(view.zt_address, [5, 4, 3, 2, 1]);

        let status = unsafe { manytier_node_action_view(node, 5, &mut view) };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert_eq!(view.kind, ManyTierFfiActionKind::PathNegotiationReceived);
        assert_eq!(view.zt_address, [1, 1, 2, 2, 3]);
        assert_eq!(view.utility, -12);

        unsafe { manytier_node_free(node) };
    }

    #[test]
    fn new_rejects_public_identity_without_secret() {
        let public = CLIENT_SECRET.rsplit_once(':').unwrap().0;
        let mut node = ptr::null_mut();
        let status = unsafe {
            manytier_node_new(
                public.as_ptr(),
                public.len(),
                DEFAULT_PLANET.as_ptr(),
                DEFAULT_PLANET.len(),
                1,
                &mut node,
            )
        };

        assert_eq!(status, ManyTierFfiStatus::MissingIdentitySecret);
        assert!(node.is_null());
    }

    #[test]
    fn new_rejects_null_pointers_and_bad_inputs() {
        let mut node = ptr::null_mut();
        let status = unsafe {
            manytier_node_new(
                ptr::null(),
                1,
                DEFAULT_PLANET.as_ptr(),
                DEFAULT_PLANET.len(),
                1,
                &mut node,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::NullPointer);

        let invalid_utf8 = [0xffu8];
        let status = unsafe {
            manytier_node_new(
                invalid_utf8.as_ptr(),
                invalid_utf8.len(),
                DEFAULT_PLANET.as_ptr(),
                DEFAULT_PLANET.len(),
                1,
                &mut node,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::InvalidUtf8);

        let invalid_identity = b"not-an-identity";
        let status = unsafe {
            manytier_node_new(
                invalid_identity.as_ptr(),
                invalid_identity.len(),
                DEFAULT_PLANET.as_ptr(),
                DEFAULT_PLANET.len(),
                1,
                &mut node,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::InvalidIdentity);

        let status = unsafe {
            manytier_node_new(
                CLIENT_SECRET.as_ptr(),
                CLIENT_SECRET.len(),
                b"bad-planet".as_ptr(),
                b"bad-planet".len(),
                1,
                &mut node,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::InvalidPlanet);
    }

    fn new_test_node() -> *mut ManyTierNode {
        let mut node = ptr::null_mut();
        let status = unsafe {
            manytier_node_new(
                CLIENT_SECRET.as_ptr(),
                CLIENT_SECRET.len(),
                DEFAULT_PLANET.as_ptr(),
                DEFAULT_PLANET.len(),
                1,
                &mut node,
            )
        };
        assert_eq!(status, ManyTierFfiStatus::Ok);
        assert!(!node.is_null());
        node
    }
}
