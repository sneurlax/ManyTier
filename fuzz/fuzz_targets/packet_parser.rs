#![no_main]

use libfuzzer_sys::fuzz_target;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::{
    error::ErrorPayload,
    frame::{ExtFramePayload, FramePayload},
    hello::HelloPayload,
    multicast::{MulticastFramePayload, MulticastGatherPayload, MulticastLikePayload},
    network_config::{CertificateOfMembership, NetworkConfigPayload, NetworkConfigRequestPayload, NetworkCredentialsPayload},
    ok::OkPayload,
    push_direct::PushDirectPathsPayload,
    rendezvous::RendezvousPayload,
    whois::{WhoisRequest, WhoisResponse},
};
use zerotier_protocol::{is_fragment, FragmentHeader, PacketHeader};

fuzz_target!(|data: &[u8]| {
    let _ = PacketHeader::from_bytes(data);

    if is_fragment(data) {
        let _ = FragmentHeader::from_bytes(data);
        return;
    }

    let Some(header) = PacketHeader::from_bytes(data) else {
        return;
    };
    if data.len() < 28 {
        return;
    }
    let payload = &data[28..];

    match Verb::from_byte(header.verb_id()) {
        Some(Verb::Hello) => {
            let _ = HelloPayload::deserialize(payload);
        }
        Some(Verb::Error) => {
            let _ = ErrorPayload::deserialize(payload);
        }
        Some(Verb::Ok) => {
            let _ = OkPayload::deserialize(payload);
        }
        Some(Verb::Whois) => {
            let _ = WhoisRequest::deserialize(payload);
            let _ = WhoisResponse::deserialize(payload);
        }
        Some(Verb::Rendezvous) => {
            let _ = RendezvousPayload::deserialize(payload);
        }
        Some(Verb::Frame) => {
            let _ = FramePayload::parse(payload);
        }
        Some(Verb::ExtFrame) => {
            let _ = ExtFramePayload::parse(payload);
        }
        Some(Verb::MulticastLike) => {
            let _ = MulticastLikePayload::deserialize(payload);
        }
        Some(Verb::NetworkConfigRequest) => {
            let _ = NetworkConfigRequestPayload::deserialize(payload);
        }
        Some(Verb::NetworkConfig) => {
            let _ = NetworkConfigPayload::deserialize(payload);
        }
        Some(Verb::MulticastGather) => {
            let _ = MulticastGatherPayload::deserialize(payload);
        }
        Some(Verb::MulticastFrame) => {
            let _ = MulticastFramePayload::parse(payload);
        }
        Some(Verb::PushDirectPaths) => {
            let _ = PushDirectPathsPayload::deserialize(payload);
        }
        _ => {
            let _ = NetworkCredentialsPayload::deserialize(payload);
            let _ = CertificateOfMembership::deserialize(payload);
        }
    }
});
