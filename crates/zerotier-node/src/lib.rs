#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod arp;
pub mod controller;
pub mod ethernet;
pub mod multicast;
pub mod ndp;
pub mod network;
#[cfg(feature = "native")]
pub mod network_config;
pub mod node;
pub mod path;
pub mod peer;
pub mod platform;
pub mod root;
pub mod switch;
pub mod topology;
pub mod traits;
pub mod vl2;
