#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_adaptor_sigs::Signature;

fuzz_target!(|data: [u8; 64]| {
    // fuzzed code goes here
    let r = Signature::from_bytes(data);
    let ksig_decode = k256::schnorr::Signature::try_from(data.as_slice());
    match r {
        Ok(r) => {
            // If deserialization succeeds, assert serialized bytes matches input and also ensure k256 library did not report error
            assert_eq!(r.to_bytes(), data, "roundtrip: serialization should yield input");
            assert!(ksig_decode.is_ok(), "k256 reported error {:?}", ksig_decode.err().unwrap()); // it should be possible to extract signature
        },
        Err(_) => {
            // If deserialization fails, k256 should have also reported error
            assert!(!ksig_decode.is_ok(), "expected k256 to raise error");
        }
    }
});
