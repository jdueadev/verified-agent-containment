fn events() -> core::ops::Range<u8> { 0..1 }

#[test]
fn law() {
    for e in events() { assert!(e < 9); }
}
