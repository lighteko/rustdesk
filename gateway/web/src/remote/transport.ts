import sodium from 'libsodium-wrappers';
import {hbb} from './generated/desktop';

const nonce = (counter: number) => {
  const bytes = new Uint8Array(24);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(counter), true);
  return bytes;
};

export function gatewaySocketURL(value: string, kind: 'id'|'relay', session: string, device: string): string {
  const url = new URL(value);
  const origin = new URL(location.origin.replace(/^http/, 'ws'));
  if (url.origin !== origin.origin || url.username || url.password || url.hash || url.search ||
      url.pathname !== `/ws/remote/${session}/${kind}`) throw new Error('Gateway transport URL rejected');
  url.searchParams.set('device_id', device);
  return url.href;
}

export class RemoteSocket {
  private socket: WebSocket;
  private queue: Uint8Array[] = [];
  private waiting?: {resolve(value: Uint8Array):void; reject(error: Error):void; timer: ReturnType<typeof setTimeout>};
  private stopped?: Error;
  private secret?: Uint8Array;
  private sending = 0;
  private receiving = 0;
  private signal: AbortSignal;
  private abort = () => this.close(new Error('Remote session ended'));
  readonly opened: Promise<void>;

  constructor(url: string, signal: AbortSignal, private onClose: (error: Error) => void) {
    this.signal = signal;
    this.socket = new WebSocket(url);
    this.socket.binaryType = 'arraybuffer';
    this.opened = new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(new Error('Gateway connection timed out')), 10000);
      this.socket.onopen = () => {clearTimeout(timer); resolve();};
      this.socket.onclose = () => {
        clearTimeout(timer);
        const error = this.stopped || new Error('Gateway closed the remote connection');
        const unexpected = !this.stopped;
        this.close(error); reject(error); if (unexpected) onClose(error);
      };
      this.socket.onerror = () => this.fail(new Error('Gateway connection failed'));
    });
    this.socket.onmessage = event => {
      try {
        if (!(event.data instanceof ArrayBuffer) || event.data.byteLength > 16*1024*1024) throw new Error('Invalid remote packet');
        let data: Uint8Array = new Uint8Array(event.data);
        if (this.secret) data = sodium.crypto_secretbox_open_easy(data, nonce(++this.receiving), this.secret);
        if (this.waiting) {
          const current = this.waiting; this.waiting = undefined;
          clearTimeout(current.timer); current.resolve(data);
        } else {
          if (this.queue.length >= 32) throw new Error('Remote receive queue exceeded');
          this.queue.push(data);
        }
      } catch {this.fail(new Error('Remote packet authentication failed'));}
    };
    signal.addEventListener('abort', this.abort, {once:true});
    if (signal.aborted) this.abort();
  }

  private fail(error: Error) {if (!this.stopped) {this.close(error); this.onClose(error);}}

  secure(key: Uint8Array) {
    if (this.secret || this.queue.length) throw new Error('Invalid key exchange state');
    this.secret = key;
  }

  send(data: Uint8Array) {
    if (this.stopped || this.socket.readyState !== WebSocket.OPEN) throw this.stopped || new Error('Remote socket is closed');
    if (this.socket.bufferedAmount > 1024*1024) throw new Error('Remote send queue exceeded');
    if (this.secret) data = sodium.crypto_secretbox_easy(data, nonce(++this.sending), this.secret);
    this.socket.send(new Uint8Array(data));
  }

  message(value: hbb.IMessage) {this.send(hbb.Message.encode(value).finish());}
  rendezvous(value: hbb.IRendezvousMessage) {this.send(hbb.RendezvousMessage.encode(value).finish());}

  next(timeout = 30000): Promise<Uint8Array> {
    if (this.stopped) return Promise.reject(this.stopped);
    if (this.queue.length) return Promise.resolve(this.queue.shift()!);
    if (this.waiting) return Promise.reject(new Error('Concurrent remote packet read'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.close(new Error('Remote PC response timed out')), timeout);
      this.waiting = {resolve, reject, timer};
    });
  }

  close(error = new Error('Remote session ended')) {
    if (this.stopped) return;
    this.stopped = error;
    this.signal.removeEventListener('abort', this.abort);
    if (this.waiting) {clearTimeout(this.waiting.timer); this.waiting.reject(error); this.waiting = undefined;}
    this.queue = [];
    this.secret?.fill(0); this.secret = undefined;
    if (this.socket.readyState === WebSocket.CONNECTING || this.socket.readyState === WebSocket.OPEN) this.socket.close();
  }
}

export async function verifyHost(signed: Uint8Array, serverKey: string, peer: string): Promise<Uint8Array> {
  await sodium.ready;
  const key = sodium.from_base64(serverKey, sodium.base64_variants.ORIGINAL);
  if (key.length !== 32 || !signed.length) throw new Error('Missing trusted RustDesk server key');
  const identity = hbb.IdPk.decode(sodium.crypto_sign_open(signed, key));
  if (identity.id !== peer || identity.pk.length !== 32) throw new Error('Remote PC identity mismatch');
  return identity.pk;
}

export async function securePeer(socket: RemoteSocket, signedKey: Uint8Array, serverKey: string, peer: string) {
  const hostKey = await verifyHost(signedKey, serverKey, peer);
  const first = hbb.Message.decode(await socket.next(10000));
  if (!first.signedId) throw new Error('Remote PC did not offer an encrypted connection');
  const identity = hbb.IdPk.decode(sodium.crypto_sign_open(first.signedId.id!, hostKey));
  if (identity.id !== peer || identity.pk.length !== 32) throw new Error('Remote PC key exchange identity mismatch');
  const pair = sodium.crypto_box_keypair();
  const secret = sodium.crypto_secretbox_keygen();
  try {
    socket.message({publicKey:{asymmetricValue:pair.publicKey, symmetricValue:sodium.crypto_box_easy(secret, nonce(0), identity.pk, pair.privateKey)}});
    socket.secure(secret);
  } finally {pair.privateKey.fill(0);}
}
