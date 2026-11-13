import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client, Result, startGuard, EXIT_LICENSE, AuthGoError, b64 } from "../index.js";
const sleep = ms => new Promise(r => setTimeout(r, ms));
function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authgo-guard-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const vector = JSON.parse(fs.readFileSync(new URL("../../vectors/v2.json", import.meta.url)));
  const config = "authgo2." + b64(Buffer.from(JSON.stringify({url:"http://127.0.0.1:1",app_key:"test",app_secret:"secret",public_key:Buffer.from(vector.ed25519_public,"base64url").toString("base64"),gateway_key:vector.gateway_public})));
  const state = { calls: 0, releases: 0, code: null, status: "online", block: null };
  const value = c => { c.state.heartbeat_interval=1; return new Result(c, { features:{export:true,nested:{x:1}},next_check_in:state.nextCheck ?? 1,floating:true}, "proof", Buffer.alloc(32),state.status, c.now()+30); };
  mock.method(Client.prototype,"check",async function(key){ state.key=key; if(state.code)throw new AuthGoError(state.code);return value(this); });
  mock.method(Client.prototype,"verify",async function(){state.calls++; if(state.block)await state.block;if(state.code)throw new AuthGoError(state.code);return value(this);});
  mock.method(Client.prototype,"heartbeat",async function(){state.heartbeats=(state.heartbeats ?? 0)+1;state.calls++;if(state.code)throw new AuthGoError(state.code);return value(this);});
  mock.method(Client.prototype,"validate",function(ticket){assert.equal(ticket,"proof");if(state.code)throw new AuthGoError(state.code);});
  mock.method(Client.prototype,"releaseSeat",async function(){state.releases++;if(state.releaseCode)throw new AuthGoError(state.releaseCode);});
  t.after(()=>mock.restoreAll());
  return { state, options:{config,cacheDir:dir,fingerprint:"a".repeat(64),license:"customer"} };
}
test("guard requires explicit config; initial failure never schedules", async t => {
  await assert.rejects(startGuard({}), {code:"SDK_INVALID_CONFIG"});
  const {state,options}=setup(t);state.code="LICENSE_REVOKED";
  await assert.rejects(startGuard(options),{code:state.code});await sleep(20);assert.equal(state.calls,0);
});
test("snapshots, local require, unref timer and close cancellation",async t=>{
  const {state,options}=setup(t);
  const original=setTimeout;const timers=[];
  mock.method(globalThis,"setTimeout",function(...args){const timer=original(...args);timers.push(timer);return timer;});
  const g=await startGuard(options);
  assert.equal(timers[0].hasRef(),false);
  const r=g.result();r.features.nested.x=99;assert.equal(g.result().features.nested.x,1);
  const before=state.calls;g.require("export");assert.equal(state.calls,before);
  assert.throws(()=>g.require("missing"),{code:"INVALID_POLICY"});
  await sleep(30);const active=timers.filter(timer=>!timer._destroyed);assert.ok(active.some(timer=>!timer.hasRef()));
  await Promise.all([g.close(),g.close()]);assert.equal(state.releases,1);
  assert.throws(()=>g.require(),{code:"SDK_NOT_ACTIVATED"});
  const count=state.calls;await sleep(1100);assert.equal(state.calls,count);assert.equal(EXIT_LICENSE,77);
});
test("grace notifies without completion; final failure resolves done",async t=>{
  const {state,options}=setup(t);
  for(const status of ["grace"]){
    state.status=status;state.code=null;let changed;
    const observed=new Promise(resolve=>{changed=resolve;});
    const g=await startGuard({...options,onChange:changed});let done=false;g.done.then(()=>done=true);
    await Promise.race([observed,sleep(1800).then(()=>{throw Error("callback timeout");})]);assert.equal(done,false);assert.equal(g.result().status,status);
    state.code=status==="grace"?"SDK_GRACE_EXPIRED":"LICENSE_REVOKED";
    await Promise.race([g.done,sleep(1800).then(()=>{throw Error("done timeout");})]);
    assert.equal(g.error.code,state.code);assert.throws(()=>g.require(),{code:state.code});await g.close();
  }
});
test("close bounded even if in-flight request ignores cancellation",async t=>{
  const {state,options}=setup(t);let release;state.block=new Promise(resolve=>release=resolve);
  const g=await startGuard(options);await sleep(30);const start=Date.now();
  await assert.rejects(g.close(),{code:"SDK_NETWORK_ERROR"});assert.ok(Date.now()-start<5300);
  release();await sleep(30);assert.equal(state.releases,0);
});

test("only license defaults from environment; release errors do not complete done",async t=>{
  const {state,options}=setup(t);
  const oldLicense=process.env.AUTHGO_LICENSE, oldConfig=process.env.AUTHGO_CONFIG;
  process.env.AUTHGO_LICENSE="customer-env";process.env.AUTHGO_CONFIG="attacker";
  try {
    await assert.rejects(startGuard({license:"customer"}),{code:"SDK_INVALID_CONFIG"});
    const g=await startGuard({...options,license:undefined});assert.equal(state.key,"customer-env");
    state.releaseCode="SDK_NETWORK_ERROR";let done=false;g.done.then(()=>done=true);
    await assert.rejects(g.close(),{code:"SDK_NETWORK_ERROR"});assert.equal(done,false);assert.equal(g.error,undefined);
  } finally {
    if(oldLicense===undefined)delete process.env.AUTHGO_LICENSE;else process.env.AUTHGO_LICENSE=oldLicense;
    if(oldConfig===undefined)delete process.env.AUTHGO_CONFIG;else process.env.AUTHGO_CONFIG=oldConfig;
  }
});

test("heartbeat uses signed response metadata, absent from the signed grant",async t=>{
  const {state,options}=setup(t);state.nextCheck=10;
  const g=await startGuard(options);
  try {
    assert.equal(g.result().data.heartbeat_interval,undefined);
    assert.equal(g.result().heartbeatInterval,1);
    await sleep(1150);assert.equal(state.heartbeats,1);assert.ok(state.calls<=3);
  } finally {await g.close();}
});
