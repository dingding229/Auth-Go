// Independent Node built-in crypto check; not an SDK or runtime loader.
// Run on the test server: node pack/testdata/verify-vector.cjs
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const v = JSON.parse(fs.readFileSync(`${__dirname}/../../sdk/vectors/payload-envelope.json`));
const hex = s => Buffer.from(s, 'hex');
const b64 = s => Buffer.from(s, 'base64url');
const H = b => crypto.createHash('sha256').update(b).digest();
const join = (...b) => Buffer.concat(b);
const lp = s => { const b = Buffer.from(s); const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return join(n,b); };
const p = v.payload;
const A = join(Buffer.from('authgo-payload-envelope-v2\0'), ...[p.app_key,p.version,p.built_at,p.key_id,p.config].map(lp),H(b64(p.manifest)),b64(p.envelope.e));
assert.equal(A.toString('hex'),v.envelope_aad_hex);
const privateKey = crypto.createPrivateKey({format:'der',type:'pkcs8',key:join(hex('302e020100300506032b656e04220420'),hex(v.recipient_private_hex))});
const publicKey = crypto.createPublicKey({format:'der',type:'spki',key:join(hex('302a300506032b656e032100'),b64(p.envelope.e))});
const shared = crypto.diffieHellman({privateKey,publicKey});
assert.equal(shared.toString('hex'),v.shared_hex);
const kek = Buffer.from(crypto.hkdfSync('sha256',shared,H(A),Buffer.from('authgo/payload/v1/wrap'),32));
assert.equal(kek.toString('hex'),v.kek_hex);
function open(key,nonce,cipher,aad) {
  const d=crypto.createDecipheriv('aes-256-gcm',key,nonce); d.setAAD(aad); d.setAuthTag(cipher.subarray(-16)); return join(d.update(cipher.subarray(0,-16)),d.final());
}
const key = open(kek,b64(p.envelope.n),b64(p.envelope.c),A);
assert.equal(key.toString('hex'),v.content_key_hex);
const B=H(join(A,b64(p.envelope.n),b64(p.envelope.c)));
assert.equal(B.toString('hex'),v.binding_hex);
for (const c of v.chunks) {
  const nonce=Buffer.alloc(12);nonce.writeUInt32BE(c.file);nonce.writeBigUInt64BE(BigInt(c.chunk),4);
  const aad=join(Buffer.from('authgo-payload-chunk-v1\0'),B,nonce,Buffer.from([c.last?1:0]));
  assert.equal(nonce.toString('hex'),c.nonce_hex);assert.equal(aad.toString('hex'),c.aad_hex);
  const plain=c.plain_hex!==undefined?hex(c.plain_hex):Buffer.alloc(c.plain_repeat_count,hex(c.plain_repeat_hex));
  const e=crypto.createCipheriv('aes-256-gcm',key,nonce);e.setAAD(aad);const cipher=join(e.update(plain),e.final(),e.getAuthTag());
  if(c.cipher_hex!==undefined)assert.equal(cipher.toString('hex'),c.cipher_hex);
  else {assert.equal(H(cipher).toString('hex'),c.cipher_sha256_hex);assert.equal(cipher.subarray(0,32).toString('hex'),c.cipher_first32_hex);assert.equal(cipher.subarray(-16).toString('hex'),c.tag_hex);}
  assert.deepEqual(open(key,nonce,cipher,aad),plain);
}
console.log('payload independent Node crypto vector: PASS');
