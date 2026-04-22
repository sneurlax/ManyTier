#![no_main]

use libfuzzer_sys::fuzz_target;
use zerotier_node::controller::dictionary::Dictionary;

fuzz_target!(|data: &[u8]| {
    let _ = Dictionary::deserialize(data);
});
