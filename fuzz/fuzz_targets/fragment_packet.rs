#![no_main]

use libfuzzer_sys::fuzz_target;
use zerotier_protocol::fragment::fragment_packet;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let mtu = u16::from_le_bytes([data[0], data[1]]) as usize;
    let packet = &data[2..];

    let _ = fragment_packet(packet, mtu);
});
