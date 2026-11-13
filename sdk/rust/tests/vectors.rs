use authgo::*;
use serde_json::{json, Value};
fn read(file: &str) -> Value {
    serde_json::from_slice(&std::fs::read(format!("../vectors/{file}")).expect("fixture"))
        .expect("json")
}
fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().expect("field")
}
#[test]
fn all_vectors() {
    let v = read("v2.json");
    let h = read("hkdf.json");
    assert_eq!(
        derive(
            &hex(&h["ikm_hex"]),
            &hex(&h["salt_hex"]),
            &hex(&h["info_hex"]),
            h["length"].as_u64().expect("length") as usize
        )
        .expect("hkdf"),
        hex(&h["okm_hex"])
    );
    let secret = x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(hex(&v["ephemeral_private_hex"])).expect("private"),
    );
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(decode(s(&v, "gateway_public")).expect("public")).expect("public"),
    ));
    use sha2::{Digest, Sha256};
    let aad = hex(&v["request_aad_hex"]);
    for direction in ["request", "response"] {
        assert_eq!(
            derive(
                shared.as_bytes(),
                &Sha256::digest(&aad),
                format!("authgo/v2/{direction}").as_bytes(),
                32
            )
            .expect("derive"),
            hex(&v[format!("{direction}_key_hex")])
        );
    }
    let p = open(
        &hex(&v["request_key_hex"]),
        &decode(s(&v["request"], "n")).expect("n"),
        &decode(s(&v["request"], "c")).expect("c"),
        &aad,
    )
    .expect("open");
    assert_eq!(p, hex(&v["padding_hex"]));
    assert_eq!(unpad(&p).expect("padding"), s(&v, "inner").as_bytes());
    let res = &v["response"];
    assert_eq!(
        unpad(
            &open(
                &hex(&v["response_key_hex"]),
                &decode(s(res, "n")).expect("n"),
                &decode(s(res, "c")).expect("c"),
                &hex(&v["response_aad_hex"])
            )
            .expect("open")
        )
        .expect("unpad"),
        s(&v, "response_plain").as_bytes()
    );
    let pubkey = decode(s(&v, "ed25519_public")).expect("public");
    let p: Vec<_> = s(&v, "ticket").split('.').collect();
    assert!(verify(
        &pubkey,
        &[
            b"authgo-ticket-v2\0".as_slice(),
            decode(p[0]).expect("p").as_slice()
        ]
        .concat(),
        &decode(p[1]).expect("sig")
    ));
    assert!(!verify(
        &pubkey,
        &[
            b"invalid-domain\0".as_slice(),
            decode(p[0]).unwrap().as_slice()
        ]
        .concat(),
        &decode(p[1]).unwrap()
    ));
    let key = derive(
        &hex(&v["unlock_seed_hex"]),
        &[],
        format!("authgo-unlock-v2\0{}", s(&v, "unlock_label")).as_bytes(),
        32,
    )
    .expect("resource");
    assert_eq!(key, hex(&v["unlock_key_hex"]));
    let p: Vec<_> = s(&v, "resource").split('.').collect();
    assert_eq!(
        open(
            &key,
            &decode(p[1]).expect("n"),
            &decode(p[2]).expect("c"),
            b"authgo-resource-v2\0settings"
        )
        .expect("resource"),
        b"hello"
    );
    let u = read("update-response.json");
    let mut cases = vec![u.clone()];
    cases.extend(u["docker_cases"].as_array().expect("cases").iter().cloned());
    use base64::{engine::general_purpose::STANDARD, Engine};
    for c in cases {
        let e = &c["response"];
        let raw = canonical(&json!({"code":e["code"],"data":e["data"],"ts":e["ts"]}));
        assert_eq!(raw, s(&c, "canonical_signed"));
        assert!(verify(
            &STANDARD.decode(s(&c, "public_key")).expect("public"),
            raw.as_bytes(),
            &STANDARD.decode(s(&c, "signature")).expect("sig")
        ));
    }
    let errors = read("error-classification.json");
    for c in errors["cases"].as_array().expect("cases") {
        assert_eq!(
            c["authenticated"] == true && !temporary(s(c, "code")),
            c["clear_cache"] == true
        );
    }
    for c in errors["update_cases"].as_array().expect("cases") {
        assert_eq!(c["clear_cache"], false);
    }
    println!("{{\"language\":\"rust\",\"vectors\":\"PASS\"}}");
}
#[test]
fn fingerprint_vectors() {
    let v = read("fingerprint.json");
    for c in v["cases"].as_array().expect("cases") {
        assert_eq!(
            identity_hash(s(c, "machine"), s(c, "mac"), s(c, "cpu")).expect("identity"),
            s(c, "expected")
        );
    }
}
#[test]
fn canonical_vectors() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let c = read("canonical.json");
    assert_eq!(
        canonical(&parse(s(&c, "raw").as_bytes()).expect("parse")),
        s(&c, "canonical")
    );
    assert!(verify(
        &STANDARD.decode(s(&c, "public_key")).expect("key"),
        s(&c, "canonical").as_bytes(),
        &STANDARD.decode(s(&c, "signature")).expect("sig")
    ));
    for invalid in c["invalid"].as_array().expect("invalid") {
        assert!(parse(invalid.as_str().expect("string").as_bytes()).is_err());
    }
}
#[test]
fn hmac_vector() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let v = read("v2.json");
    let raw = s(&v, "inner");
    let inner: Value = serde_json::from_str(raw).expect("inner");
    let start = raw.find("\"body\":").expect("body") + 7;
    let body = &raw[start..raw.len() - 1];
    let input = format!(
        "{}{}{}{}",
        s(&inner, "op"),
        s(&inner, "timestamp"),
        s(&inner, "nonce"),
        hash(body.as_bytes())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(b"test-secret-only").expect("key");
    mac.update(input.as_bytes());
    let actual: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(actual, s(&inner, "signature"));
}

#[test]
fn license_key_vectors() {
    for c in read("license-key.json")["cases"].as_array().expect("cases") {
        let result = validate_key(s(c, "key"));
        assert_eq!(result.is_ok(), c["valid"] == true, "{}", s(c, "name"));
        if let Err(e) = result {
            assert_eq!(e.code(), s(c, "code"));
        }
    }
}
#[test]
fn linux_cpu_vectors() {
    for c in read("fingerprint.json")["cpuinfo_cases"]
        .as_array()
        .expect("cases")
    {
        let cpu = parse_linux_cpu(s(c, "cpuinfo"));
        assert_eq!(cpu, s(c, "cpu"), "{}", s(c, "name"));
        if !cpu.is_empty() {
            assert_eq!(
                identity_hash(s(c, "machine"), s(c, "mac"), &cpu).expect("hash"),
                s(c, "expected")
            );
        }
    }
}

#[test]
fn container_vectors() {
    let v = read("container-identity.json");
    for c in v["detection"].as_array().expect("detection") {
        assert_eq!(
            container::detect(
                |p| c["files"][p]
                    .as_str()
                    .map(|s| s.as_bytes().to_vec())
                    .ok_or_else(|| std::io::ErrorKind::NotFound.into()),
                |k| c["env"][k].as_str().map(str::to_string)
            ),
            c["expected"] == true
        );
    }
    for c in v["fingerprints"].as_array().expect("fingerprints") {
        assert_eq!(container::fingerprint(s(c, "id")), s(c, "expected"));
    }
}

#[test]
fn instance_session_vectors() {
    let v = read("instance-session.json");
    let v = &v["instance_session"];
    assert_eq!(
        decode(s(v, "valid")).expect("valid session").len() as u64,
        v["bytes"].as_u64().expect("bytes")
    );
    for value in v["invalid"].as_array().expect("invalid") {
        assert!(!decode(value.as_str().expect("value"))
            .is_ok_and(|raw| raw.len() as u64 == v["bytes"].as_u64().expect("bytes")));
    }
    assert_eq!(v["persist_in_cache"], false);
}
