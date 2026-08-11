//! Emit IRF/1 test vectors as JSON on stdout.
//!
//! These vectors are the normative artefact of the spec. Any implementation that
//! reproduces them byte-for-byte is interoperable; any that does not is wrong.
//! Run: `cargo run --example gen_vectors > vectors.json`

use inverba_core::build::{self, SignerInput, SCOPE_OBSERVATION};
use inverba_core::dcbor::{self, Value};
use inverba_core::domain::Domain;
use inverba_core::merkle;
use inverba_core::preimage::{self, alg, hash_alg, FORMAT_V1};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn main() {
    let mut out: Vec<String> = Vec::new();

    // ---- dCBOR encoding vectors -----------------------------------------
    let mut dcbor_v: Vec<String> = Vec::new();
    let cases: Vec<(&str, Value)> = vec![
        ("uint_0", Value::Uint(0)),
        ("uint_23", Value::Uint(23)),
        ("uint_24", Value::Uint(24)),
        ("uint_65535", Value::Uint(65535)),
        ("uint_65536", Value::Uint(65536)),
        ("nint_minus_1", Value::Nint(0)),
        ("nint_minus_8_ed25519_alg", Value::Nint(7)),
        ("nint_minus_49_mldsa65_alg", Value::Nint(48)),
        ("bytes_empty", Value::Bytes(vec![])),
        ("bytes_deadbeef", Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
        ("text_ascii", Value::Text(String::from("inverba"))),
        ("text_utf8", Value::Text(String::from("caf\u{e9}"))),
        ("bool_true", Value::Bool(true)),
        ("null", Value::Null),
        ("array_empty", Value::Array(vec![])),
        ("map_empty", Value::Map(vec![])),
    ];
    for (name, v) in &cases {
        dcbor_v.push(format!(
            "{{\"name\":{},\"cbor\":{}}}",
            q(name),
            q(&hex(&dcbor::encode(v)))
        ));
    }
    // Map key ordering: keys sort by encoded bytes, so "z" (1 char) precedes
    // "aa" (2 chars) because the length is part of the head byte.
    let sorted = Value::map(vec![
        (Value::Text(String::from("aa")), Value::Uint(1)),
        (Value::Text(String::from("z")), Value::Uint(2)),
        (Value::Uint(1), Value::Uint(3)),
    ])
    .expect("map");
    dcbor_v.push(format!(
        "{{\"name\":{},\"cbor\":{},\"note\":{}}}",
        q("map_key_order_by_encoded_bytes"),
        q(&hex(&dcbor::encode(&sorted))),
        q("integer key 1 sorts before text keys; \"z\" sorts before \"aa\"")
    ));
    out.push(format!("\"dcbor\":[{}]", dcbor_v.join(",")));

    // ---- rejection vectors ----------------------------------------------
    let rejects: Vec<(&str, Vec<u8>)> = vec![
        ("non_minimal_uint", vec![0x18, 0x05]),
        ("indefinite_bstr", vec![0x5f, 0x41, 0x61, 0xff]),
        ("float16", vec![0xf9, 0x00, 0x00]),
        ("float64", vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("semantic_tag_0", vec![0xc0, 0x61, 0x61]),
        ("undefined", vec![0xf7]),
        ("unsorted_map_keys", vec![0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x01]),
        ("duplicate_map_keys", vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x01]),
        ("trailing_bytes", vec![0x01, 0x02]),
        ("truncated_bstr", vec![0x42, 0x01]),
    ];
    let rv: Vec<String> = rejects
        .iter()
        .map(|(n, b)| {
            debug_assert!(dcbor::decode_canonical(b).is_err());
            format!("{{\"name\":{},\"cbor\":{}}}", q(n), q(&hex(b)))
        })
        .collect();
    out.push(format!("\"dcbor_must_reject\":[{}]", rv.join(",")));

    // ---- domain tags -----------------------------------------------------
    let doms = [
        ("record", Domain::Record),
        ("manifest", Domain::Manifest),
        ("anchor", Domain::Anchor),
        ("witness", Domain::Witness),
        ("renewal", Domain::Renewal),
    ];
    let dv: Vec<String> = doms
        .iter()
        .map(|(n, d)| {
            format!(
                "{{\"name\":{},\"tag\":{},\"tag_hex\":{}}}",
                q(n),
                q(&String::from_utf8_lossy(d.tag())),
                q(&hex(d.tag()))
            )
        })
        .collect();
    out.push(format!("\"domains\":[{}]", dv.join(",")));

    // ---- merkle vectors --------------------------------------------------
    let mut mv: Vec<String> = Vec::new();
    for n in [1usize, 2, 3, 4, 5, 7, 8, 9] {
        let data: Vec<Vec<u8>> = (0..n).map(|i| vec![u8::try_from(i).unwrap_or(0)]).collect();
        let leaves: Vec<merkle::Hash> = data.iter().map(|d| merkle::leaf_hash(d)).collect();
        let root = merkle::root(&leaves).expect("root");
        let idx = n.saturating_sub(1).min(3);
        let proof = merkle::inclusion_proof(&leaves, idx).expect("proof");
        let ph: Vec<String> = proof.iter().map(|h| q(&hex(h))).collect();
        mv.push(format!(
            "{{\"size\":{},\"leaf_data_hex\":[{}],\"root\":{},\"proof_index\":{},\"proof\":[{}]}}",
            n,
            data.iter()
                .map(|d| q(&hex(d)))
                .collect::<Vec<_>>()
                .join(","),
            q(&hex(&root)),
            idx,
            ph.join(",")
        ));
    }
    out.push(format!("\"merkle\":[{}]", mv.join(",")));

    // Consistency vector: 5 -> 8
    let leaves8: Vec<merkle::Hash> = (0..8u8).map(|i| merkle::leaf_hash(&[i])).collect();
    let leaves5: Vec<merkle::Hash> = leaves8.iter().copied().take(5).collect();
    let r8 = merkle::root(&leaves8).expect("r8");
    let r5 = merkle::root(&leaves5).expect("r5");
    let cp = merkle::consistency_proof(&leaves8, 5).expect("cp");
    out.push(format!(
        "\"merkle_consistency\":{{\"m\":5,\"root_m\":{},\"n\":8,\"root_n\":{},\"proof\":[{}]}}",
        q(&hex(&r5)),
        q(&hex(&r8)),
        cp.iter().map(|h| q(&hex(h))).collect::<Vec<_>>().join(",")
    ));

    // ---- payload + preimage + envelope ----------------------------------
    let content = b"<html><body>hello inverba</body></html>";
    let content_hash = merkle::leaf_hash(content); // any 32-byte digest works as a fixture
    let payload = build::observation_payload(
        "https://example.test/page",
        hash_alg::SHA_256,
        &content_hash,
        u64::try_from(content.len()).unwrap_or(0),
        "text/html",
        1_753_400_000,
        b"node-alpha",
        SCOPE_OBSERVATION,
    )
    .expect("payload");

    let bp = preimage::body_protected(FORMAT_V1).expect("bp");
    let sp_ed = preimage::sign_protected(alg::ED25519, b"node-alpha").expect("sp");
    let sp_ml = preimage::sign_protected(alg::ML_DSA_65, b"node-alpha").expect("sp");

    let pre_ed = preimage::sig_structure(&bp, &sp_ed, Domain::Record, &payload);
    let pre_ml = preimage::sig_structure(&bp, &sp_ml, Domain::Record, &payload);
    let pre_ed_manifest = preimage::sig_structure(&bp, &sp_ed, Domain::Manifest, &payload);

    out.push(format!(
        "\"record\":{{\"content_hex\":{},\"content_hash\":{},\"payload\":{},\"body_protected\":{},\"sign_protected_ed25519\":{},\"sign_protected_mldsa65\":{},\"sig_structure_record_ed25519\":{},\"sig_structure_record_mldsa65\":{},\"sig_structure_manifest_ed25519\":{}}}",
        q(&hex(content)),
        q(&hex(&content_hash)),
        q(&hex(&payload)),
        q(&hex(&bp)),
        q(&hex(&sp_ed)),
        q(&hex(&sp_ml)),
        q(&hex(&pre_ed)),
        q(&hex(&pre_ml)),
        q(&hex(&pre_ed_manifest))
    ));

    // Envelope with deterministic placeholder signatures so the wire shape is
    // pinned. Real signatures are substituted by the Python interop check.
    let signers = vec![
        SignerInput {
            alg_id: alg::ED25519,
            kid: b"node-alpha".to_vec(),
            signature: vec![0x11; 64],
        },
        SignerInput {
            alg_id: alg::ML_DSA_65,
            kid: b"node-alpha".to_vec(),
            signature: vec![0x22; 3309],
        },
    ];
    let env = build::envelope(FORMAT_V1, &payload, &signers).expect("env");
    out.push(format!(
        "\"envelope\":{{\"placeholder_sig_ed25519_hex\":{},\"placeholder_sig_mldsa65_len\":{},\"cose_sign\":{}}}",
        q(&hex(&[0x11; 64])),
        3309,
        q(&hex(&env))
    ));

    println!("{{{}}}", out.join(","));
}
