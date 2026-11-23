fn events() -> core::ops::Range<u8> { 0..7 }

#[test]
fn law() {
    for e in events() { assert!(e < 9); }
}
