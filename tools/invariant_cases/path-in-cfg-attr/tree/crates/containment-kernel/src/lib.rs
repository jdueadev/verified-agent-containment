#![no_std]
#![forbid(unsafe_code)]
pub fn f(x: u8) -> u8 { x }
#[cfg_attr(all(), path = "payload.rs")]
mod payload;
