#![no_main]

use libfuzzer_sys::fuzz_target;
use zerotier_protocol::verbs::network_config::{
    CertificateOfMembership, NetworkConfigPayload, NetworkConfigRequestPayload,
    NetworkCredentialsPayload,
};

fuzz_target!(|data: &[u8]| {
    let _ = NetworkConfigRequestPayload::deserialize(data);
    let _ = NetworkConfigPayload::deserialize(data);
    let _ = NetworkCredentialsPayload::deserialize(data);
    let _ = CertificateOfMembership::deserialize(data);
});
