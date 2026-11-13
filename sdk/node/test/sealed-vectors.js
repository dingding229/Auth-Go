import assert from "node:assert/strict";
import crypto from "node:crypto";
import * as a from "../index.js";
import { vector, hex } from "./payload-vectors.js";

export function checkChunkVectors() {
  const v = vector("payload-envelope.json"),
    payload = a.parsePayload(JSON.stringify(v.payload));
  assert.equal(payload.payloadBinding().toString("hex"), v.binding_hex);
  const files = new Map(),
    plains = new Map();
  for (const chunk of v.chunks) {
    const plain =
      chunk.plain_hex !== undefined
        ? hex(chunk.plain_hex)
        : Buffer.alloc(chunk.plain_repeat_count, hex(chunk.plain_repeat_hex));
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(chunk.file);
    nonce.writeBigUInt64BE(BigInt(chunk.chunk), 4);
    const aad = Buffer.concat([
      Buffer.from("authgo-payload-chunk-v1\0"),
      payload.payloadBinding(),
      nonce,
      Buffer.from([Number(chunk.last)]),
    ]);
    assert.equal(nonce.toString("hex"), chunk.nonce_hex);
    assert.equal(aad.toString("hex"), chunk.aad_hex);
    const c = crypto.createCipheriv(
      "aes-256-gcm",
      hex(v.content_key_hex),
      nonce,
    );
    c.setAAD(aad);
    const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    if (chunk.cipher_hex !== undefined)
      assert.equal(ct.toString("hex"), chunk.cipher_hex);
    else {
      assert.equal(
        ct.subarray(0, 32).toString("hex"),
        chunk.cipher_first32_hex,
      );
      assert.equal(ct.subarray(-16).toString("hex"), chunk.tag_hex);
      assert.equal(a.sha(ct), chunk.cipher_sha256_hex);
    }
    files.set(
      chunk.file,
      Buffer.concat([files.get(chunk.file) || Buffer.alloc(0), ct]),
    );
    plains.set(
      chunk.file,
      Buffer.concat([plains.get(chunk.file) || Buffer.alloc(0), plain]),
    );
  }
  for (const [index, ciphertext] of files) {
    const blocks = [
      ...a.decryptPayloadFile(
        payload,
        hex(v.content_key_hex),
        index,
        ciphertext,
      ),
    ];
    assert.ok(blocks.every((b) => b.length <= 1 << 20));
    assert.deepEqual(Buffer.concat(blocks), plains.get(index));
    assert.equal(
      a.payloadCipherSize(plains.get(index).length),
      BigInt(ciphertext.length),
    );
  }
}
