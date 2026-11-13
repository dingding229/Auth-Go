import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import * as a from "../index.js";
import * as p from "../payload.js";
export const vector = (name) =>
  JSON.parse(
    fs.readFileSync(new URL("../../vectors/" + name, import.meta.url), "utf8"),
  );
export const hex = (text) => Buffer.from(text, "hex");
export const rawPublic = (key) =>
  key.export({ format: "der", type: "spki" }).subarray(-32);
export const privateKey = (raw) =>
  crypto.createPrivateKey({
    key: Buffer.concat([hex("302e020100300506032b656e04220420"), raw]),
    format: "der",
    type: "pkcs8",
  });
export function checkPayloadVectors() {
  const v = vector("payload-unlock-v2.json"),
    payload = a.parsePayload(a.canonical(v.payload)),
    priv = hex(v.client_private_hex),
    challenge = hex(v.challenge_hex);
  const ephemeral = rawPublic(crypto.createPublicKey(privateKey(priv)));
  assert.equal(ephemeral.toString("hex"), v.client_public_hex);
  const aad = p.payloadRewrapAAD(payload, ephemeral, challenge);
  assert.equal(aad.toString("hex"), v.rewrap_aad_hex);
  const shared = a.sharedSecret(priv, hex(v.server_public_hex));
  assert.equal(shared.toString("hex"), v.shared_hex);
  assert.equal(a.sha(aad), v.salt_hex);
  assert.equal(
    a.hkdf(shared, hex(v.salt_hex), Buffer.from(v.hkdf_info)).toString("hex"),
    v.kek_hex,
  );
  assert.equal(
    p.unwrapPayload(payload, v.response, priv, challenge).toString("hex"),
    v.content_key_hex,
  );
  const original = vector("payload-envelope.json");
  assert.equal(
    a
      .parsePayload(a.canonical(original.payload))
      .payloadBinding()
      .toString("hex"),
    original.binding_hex,
  );
  const originalPayload = a.parsePayload(a.canonical(original.payload));
  const envelopeAAD = Buffer.concat([
    p.payloadAAD(originalPayload),
    a.unb64(originalPayload.envelope.e),
  ]);
  assert.equal(envelopeAAD.toString("hex"), original.envelope_aad_hex);
  assert.equal(
    a.unb64(originalPayload.manifest).toString(),
    original.manifest_utf8,
  );
  const envelopeShared = a.sharedSecret(
    hex(original.recipient_private_hex),
    a.unb64(originalPayload.envelope.e),
  );
  assert.equal(envelopeShared.toString("hex"), original.shared_hex);
  assert.equal(a.sha(envelopeAAD), original.salt_hex);
  const envelopeKEK = a.hkdf(
    envelopeShared,
    hex(original.salt_hex),
    Buffer.from("authgo/payload/v1/wrap"),
  );
  assert.equal(envelopeKEK.toString("hex"), original.kek_hex);
  assert.equal(
    a
      .open(
        envelopeKEK,
        a.unb64(originalPayload.envelope.n),
        a.unb64(originalPayload.envelope.c),
        envelopeAAD,
      )
      .toString("hex"),
    original.content_key_hex,
  );
  // Authenticate both manifest/chunk AAD and the original envelope vector.
  for (const chunk of original.chunks) {
    const plain =
      chunk.plain_hex != null
        ? hex(chunk.plain_hex)
        : Buffer.alloc(
            chunk.plain_repeat_count,
            hex(chunk.plain_repeat_hex)[0],
          );
    const encrypted = a.seal(
      hex(original.content_key_hex),
      hex(chunk.nonce_hex),
      plain,
      hex(chunk.aad_hex),
    );
    if (chunk.cipher_hex)
      assert.equal(encrypted.toString("hex"), chunk.cipher_hex);
    if (chunk.tag_hex)
      assert.equal(encrypted.subarray(-16).toString("hex"), chunk.tag_hex);
  }
  const cache = vector("payload-cache-v2.json"),
    cp = a.parsePayload(a.canonical(cache.payload));
  const label = p.payloadCacheLabel(cp, cache.fingerprint);
  assert.equal(label.toString("hex"), cache.label_hex);
  const info = Buffer.concat([Buffer.from("authgo-unlock-v2\0"), label]);
  assert.equal(info.toString("hex"), cache.resource_info_hex);
  const key = a.hkdf(hex(cache.unlock_hash_hex), Buffer.alloc(0), info);
  assert.equal(key.toString("hex"), cache.cache_key_hex);
  const id = Buffer.alloc(8);
  id.writeBigUInt64BE(BigInt(cache.license_id));
  const fileAAD = Buffer.concat([
    Buffer.from("authgo-payload-cache-file-v2\0"),
    hex(a.sha(label)),
    id,
  ]);
  assert.equal(fileAAD.toString("hex"), cache.aad_hex);
  const cipher = a.seal(
    key,
    hex(cache.nonce_hex),
    hex(cache.material_hex),
    fileAAD,
  );
  assert.equal(cipher.toString("hex"), cache.ciphertext_hex);
  assert.equal(
    "AUTHGO-PAYLOAD-CACHE-v2." +
      a.b64(Buffer.concat([hex(cache.nonce_hex), cipher])),
    cache.file_utf8,
  );
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authgo-payload-vector-"));
  try {
    const client = new a.Client(cp.config, {
      fingerprint: cache.fingerprint,
      cacheDir: dir,
      clock: () => cache.proof_now,
    });
    assert.equal(p.cacheIdentity(client), cache.cache_identity_utf8);
    const result = new a.Result(
      client,
      client.grant(cache.ticket),
      cache.ticket,
    );
    const material = p.cacheMaterial(client, cp, result);
    assert.equal(path.basename(material.file), cache.filename);
    assert.deepEqual(material.key, key);
    assert.deepEqual(material.aad, fileAAD);
    fs.writeFileSync(material.file, cache.file_utf8, { mode: 0o600 });
    assert.equal(
      p.loadPayloadKey(client, cp, result).toString("hex"),
      cache.material_hex,
    );
    p.savePayloadKey(client, cp, result, hex(cache.material_hex));
    assert.equal(fs.statSync(material.file).mode & 0o777, 0o600);
    assert.equal(
      p.loadPayloadKey(client, cp, result).toString("hex"),
      cache.material_hex,
    );
    assert(!fs.readdirSync(dir).some((name) => name.includes("proof")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
