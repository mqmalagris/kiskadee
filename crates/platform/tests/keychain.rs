#![cfg(windows)]

use kiskadee_platform::keychain;

#[test]
fn a_secret_round_trips_through_the_os_keychain_and_deletes_cleanly() {
    keychain::init().expect("native store");
    let key = format!("test-{}", rand::random::<u64>());
    let secret = b"refresh-token-\x00\xffbinary-safe";

    keychain::put(&key, secret).expect("put");
    let read_back = keychain::get(&key).expect("get");
    keychain::delete(&key).expect("delete");
    let after_delete = keychain::get(&key).expect("get after delete");

    assert_eq!(read_back.as_deref(), Some(&secret[..]));
    assert_eq!(after_delete, None);
    keychain::delete(&key).expect("deleting a missing secret succeeds");
}
