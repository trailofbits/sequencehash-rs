//! Checks this crate against the C2SP/CCTV SequenceHash test vectors
//! (https://github.com/C2SP/CCTV/tree/main/sequencehash).
//!
//! The vectors are not vendored. Point `SEQUENCEHASH_CCTV_DIR` at the
//! `sequencehash` directory of a CCTV checkout to run them:
//!
//! ```text
//! git clone https://github.com/C2SP/CCTV /tmp/cctv
//! git -C /tmp/cctv checkout 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7
//! SEQUENCEHASH_CCTV_DIR=/tmp/cctv/sequencehash cargo test --test cctv
//! ```
//!
//! Without it the test prints a note and passes. CI always sets it. Every
//! file is checked against `tests/data/cctv.sha256` first, and the number of
//! vectors is checked, so the test can't pass on a partial or modified copy.
//!
//! The intermediate values in the vectors (`inner_hash`, `inner_header`,
//! `outer_header`) aren't exposed by the public API, so only `final_output`
//! is compared.

use std::path::Path;

use blake2::{Blake2b512, Blake2s256};
use digest::Digest;
use sequencehash::{SequenceHash, SequenceMAC};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

const ENV_DIR: &str = "SEQUENCEHASH_CCTV_DIR";
const VECTORS_PER_FILE: usize = 384;

#[test]
fn cctv() {
    let Some(dir) = std::env::var_os(ENV_DIR) else {
        eprintln!("{ENV_DIR} is not set; skipping the C2SP/CCTV vectors (see tests/cctv.rs)");
        return;
    };
    let dir = Path::new(&dir);

    let sums = include_str!("data/cctv.sha256");
    let (mut matched, mut rejected) = (0, 0);
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (want_sum, name) = line.split_once("  ").expect("malformed cctv.sha256 line");
        let data = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            hex(&Sha256::digest(&data)),
            want_sum,
            "{name}: checksum mismatch"
        );

        let vectors: Vec<Value> = serde_json::from_slice(&data).expect(name);
        assert_eq!(vectors.len(), VECTORS_PER_FILE, "{name}: vector count");
        for (i, v) in vectors.iter().enumerate() {
            let s = |k: &str| {
                v[k].as_str()
                    .unwrap_or_else(|| panic!("{name}[{i}]: missing {k}"))
            };
            let hash = s("hash_name");
            let key = unhex(s("key"));
            let customizer = unhex(s("customizer"));
            let inputs: Vec<Vec<u8>> = v["inputs"]
                .as_array()
                .unwrap_or_else(|| panic!("{name}[{i}]: missing inputs"))
                .iter()
                .map(|x| unhex(x.as_str().expect("input is not a string")))
                .collect();
            let must_fail = v["must_fail"].as_bool().unwrap_or(false);

            let got = match v["function_id"].as_u64() {
                Some(1) => mac(hash, &key, &inputs, &customizer),
                Some(2) => Some(seq_hash(hash, &inputs, &customizer)),
                other => panic!("{name}[{i}]: unknown function_id {other:?}"),
            };
            match got {
                None => {
                    assert!(
                        must_fail,
                        "{name}[{i}]: key rejected but the vector is valid"
                    );
                    rejected += 1;
                }
                Some(out) => {
                    assert!(!must_fail, "{name}[{i}]: must_fail vector was accepted");
                    assert_eq!(hex(&out), s("final_output"), "{name}[{i}]: final_output");
                    matched += 1;
                }
            }
        }
    }
    // Pin the totals, so a change in which vectors are rejected is caught.
    assert_eq!((matched, rejected), (4224, 768));
    eprintln!("C2SP/CCTV: {matched} outputs matched, {rejected} must_fail vectors rejected");
}

/// SequenceMAC output, or `None` if the key was rejected.
fn mac(hash: &str, key: &[u8], inputs: &[Vec<u8>], customizer: &[u8]) -> Option<Vec<u8>> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = SequenceMAC::<$h>::new(&key).ok()?;
            for x in inputs {
                m.add(x);
            }
            Some(m.result_with_customizer(&customizer))
        }};
    }
    match hash {
        "sha256" => run!(Sha256),
        "sha512" => run!(Sha512),
        "sha3_256" => run!(Sha3_256),
        "sha3_512" => run!(Sha3_512),
        "blake2b" => run!(Blake2b512),
        "blake2s" => run!(Blake2s256),
        other => panic!("no SequenceMAC vectors expected for {other}"),
    }
}

fn seq_hash(hash: &str, inputs: &[Vec<u8>], customizer: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($h:ty) => {{
            let mut s = SequenceHash::<$h>::new();
            for x in inputs {
                s.add(x);
            }
            s.result_with_customizer(&customizer)
        }};
    }
    match hash {
        "sha1" => run!(Sha1),
        "sha256" => run!(Sha256),
        "sha512" => run!(Sha512),
        "sha3_256" => run!(Sha3_256),
        "sha3_512" => run!(Sha3_512),
        "blake2b" => run!(Blake2b512),
        "blake2s" => run!(Blake2s256),
        other => panic!("unknown hash {other}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}
