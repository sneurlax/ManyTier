//! Controller module: storage trait and data types.
//!
//! The controller manages virtual networks, members, and IP pools.
//! This module defines the storage abstraction; implementations live
//! in zerotier-service.

pub mod config_builder;
pub mod dictionary;
pub mod engine;
pub mod ip_pool;
pub mod rules;
pub mod storage;
pub mod types;
pub mod world_gen;
