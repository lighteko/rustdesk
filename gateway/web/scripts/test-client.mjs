import assert from 'node:assert/strict';
import {writeFile, unlink} from 'node:fs/promises';
import {build} from 'vite';
import sodium from 'libsodium-wrappers';
import {hbb} from '../src/remote/generated/desktop.js';

const output = await build({configFile:false, logLevel:'error', build:{ssr:'src/remote/transport.ts', write:false, rollupOptions:{output:{inlineDynamicImports:true}}}});
const file = new URL('../src/remote/generated/test-transport.mjs', import.meta.url);
try {
  await writeFile(file, output.output[0].code);
  const {gatewaySocketURL, verifyHost, securePeer, RemoteSocket} = await import(file.href);
  globalThis.location = {origin:'https://remote.example.com'};
  const route = 'wss://remote.example.com/ws/remote/ras_test/relay';
  assert.equal(gatewaySocketURL(route,'relay','ras_test','mac'), route+'?device_id=mac');
  for (const value of [route.replace('remote.example.com','evil.example.com'), route.replace('wss:','ws:'), route.replace('ras_test','ras_other'), route+'?token=leaked']) {
    assert.throws(() => gatewaySocketURL(value,'relay','ras_test','mac'));
  }
  await sodium.ready;
  const server = sodium.crypto_sign_keypair();
  const host = sodium.crypto_sign_keypair();
  const box = sodium.crypto_box_keypair();
  const publicKey = sodium.to_base64(server.publicKey, sodium.base64_variants.ORIGINAL);
  const signed = sodium.crypto_sign(hbb.IdPk.encode({id:'mac-peer',pk:host.publicKey}).finish(),server.privateKey);
  assert.deepEqual(await verifyHost(signed,publicKey,'mac-peer'),host.publicKey);
  await assert.rejects(verifyHost(signed,publicKey,'wrong-peer'));
  const tampered = new Uint8Array(signed); tampered[0] ^= 1;
  await assert.rejects(verifyHost(tampered,publicKey,'mac-peer'));
  await assert.rejects(verifyHost(signed,'','mac-peer'));

  class TestSocket {
    static OPEN=1; static CONNECTING=0; static CLOSED=3;
    static current;
    readyState=0; bufferedAmount=0; sent=[];
    constructor(){TestSocket.current=this;queueMicrotask(()=>{this.readyState=1;this.onopen?.()})}
    send(value){this.sent.push(value)}
    close(){this.readyState=3;queueMicrotask(()=>this.onclose?.())}
    incoming(value){this.onmessage({data:new Uint8Array(value).buffer})}
  }
  globalThis.WebSocket = TestSocket;
  const abort = new AbortController();
  let failure;
  const socket = new RemoteSocket(route,abort.signal,error=>failure=error);
  await socket.opened;
  const native = TestSocket.current;
  native.incoming(hbb.Message.encode({signedId:{id:sodium.crypto_sign(hbb.IdPk.encode({id:'mac-peer',pk:box.publicKey}).finish(),host.privateKey)}}).finish());
  await securePeer(socket,signed,publicKey,'mac-peer');
  const exchange = hbb.Message.decode(native.sent[0]).publicKey;
  const nonce = new Uint8Array(24);
  const secret = sodium.crypto_box_open_easy(exchange.symmetricValue,nonce,exchange.asymmetricValue,box.privateKey);
  nonce[0]=1;
  socket.message({keyEvent:{chr:65,down:true}});
  assert.equal(hbb.Message.decode(sodium.crypto_secretbox_open_easy(native.sent[1],nonce,secret)).keyEvent.chr,65);
  const encrypted = sodium.crypto_secretbox_easy(hbb.Message.encode({misc:{closeReason:'test-close'}}).finish(),nonce,secret);
  native.incoming(encrypted);
  assert.equal(hbb.Message.decode(await socket.next()).misc.closeReason,'test-close');
  native.incoming(encrypted);
  assert.match(failure.message,/authentication failed/);
  await assert.rejects(socket.next());
  assert.equal(native.readyState,TestSocket.CLOSED);
  const otherAbort = new AbortController();
  const other = new RemoteSocket(route,otherAbort.signal,()=>{}); await other.opened;
  const pending = other.next(); otherAbort.abort();
  await assert.rejects(pending); assert.equal(TestSocket.current.readyState,TestSocket.CLOSED);
  console.log('PASS: Gateway URL binding, signed peer identity, encrypted key exchange, bidirectional packets, replay rejection and abort cleanup');
} finally {await unlink(file).catch(()=>{});}
