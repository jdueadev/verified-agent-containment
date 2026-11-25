#![no_std]
#![forbid(unsafe_code)]
pub fn f(x: u8) -> u8 { x }
const P: &str = r#include!("payload");
