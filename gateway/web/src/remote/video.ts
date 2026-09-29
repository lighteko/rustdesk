import {hbb} from './generated/desktop';

type Plane = {bytes: Uint8Array; stride: number};
type YUVFrame = {format:{width:number; height:number; chromaWidth:number; chromaHeight:number; displayWidth:number; displayHeight:number}; y:Plane; u:Plane; v:Plane};
type OGVDecoder = {init(callback:()=>void):void; processFrame(data:ArrayBuffer, callback:(ok:boolean)=>void):void; frameBuffer:YUVFrame; close():void};
type OGVLoader = {base:string; loadClass(name:string, callback:(factory:(options:object)=>Promise<OGVDecoder>)=>void, options:object):void};
declare global {interface Window {OGVLoader?: OGVLoader}}

let ogvLoading: Promise<void>|undefined;
async function loadOGV(): Promise<void> {
  if (!ogvLoading) ogvLoading = new Promise((resolve, reject) => {
    const script = document.createElement('script'); script.src = '/client/ogv/ogv.js';
    script.onload = () => resolve(); script.onerror = () => reject(new Error('Software video decoder could not be loaded'));
    document.head.append(script);
  });
  await ogvLoading;
}

export class DesktopVideo {
  private native?: VideoDecoder;
  private software?: OGVDecoder;
  private kind?: 'vp9'|'vp8';
  private timestamp = 0;
  private pending?: {timestamp:number; resolve():void; reject(error: Error):void};
  private stopped = false;
  constructor(private canvas:HTMLCanvasElement) {}

  private async configure(kind: 'vp9'|'vp8') {
    this.native?.close(); this.software?.close(); this.native = undefined; this.software = undefined;
    this.kind = kind;
    const codec = kind === 'vp9' ? 'vp09.00.10.08' : 'vp8';
    if (typeof VideoDecoder !== 'undefined' && (await VideoDecoder.isConfigSupported({codec})).supported) {
      this.native = new VideoDecoder({output:frame => {
        try {
          if (!this.stopped) {
            this.canvas.width = frame.displayWidth; this.canvas.height = frame.displayHeight;
            this.canvas.getContext('2d')!.drawImage(frame, 0, 0);
          }
          if (this.pending?.timestamp === frame.timestamp) {this.pending.resolve(); this.pending = undefined;}
        } finally {frame.close();}
      }, error:error => {this.pending?.reject(error); this.pending = undefined;}});
      this.native.configure({codec, optimizeForLatency:true});
    } else {
      await loadOGV();
      if (this.stopped) throw new Error('Remote session ended');
      const loader = window.OGVLoader!; loader.base = '/client/ogv';
      this.software = await new Promise<OGVDecoder>((resolve, reject) => {
        loader.loadClass(kind === 'vp9' ? 'OGVDecoderVideoVP9W' : 'OGVDecoderVideoVP8W', factory => {
          factory({videoFormat:{}}).then(decoder => decoder.init(() => resolve(decoder)), reject);
        }, {worker:true});
      });
    }
    if (this.stopped) {this.native?.close(); this.software?.close(); throw new Error('Remote session ended');}
  }

  async draw(value:hbb.IVideoFrame) {
    const kind = value.vp9s ? 'vp9' : value.vp8s ? 'vp8' : undefined;
    if (!kind) throw new Error('Unsupported remote video codec');
    if (this.kind !== kind) await this.configure(kind);
    const frames = (value.vp9s || value.vp8s)!.frames || [];
    if (frames.length > 60) throw new Error('Invalid remote video batch');
    for (const frame of frames) {
      if (this.stopped) throw new Error('Remote session ended');
      if (!frame.data?.length) continue;
      if (this.native) {
        const timestamp = ++this.timestamp;
        await new Promise<void>((resolve, reject) => {
          this.pending = {timestamp, resolve, reject};
          try {this.native!.decode(new EncodedVideoChunk({type:frame.key ? 'key':'delta', timestamp, data:new Uint8Array(frame.data!)}));}
          catch(error) {this.pending = undefined; reject(error);}
        });
      } else {
        const decoder = this.software!;
        await new Promise<void>((resolve, reject) => {
          decoder.processFrame(new Uint8Array(frame.data!).buffer, ok => {
            if (this.stopped) {reject(new Error('Remote session ended')); return;}
            if (!ok || !decoder.frameBuffer) {reject(new Error('Remote video decoding failed')); return;}
            this.drawYUV(decoder.frameBuffer); resolve();
          });
        });
      }
    }
  }

  private drawYUV(frame:YUVFrame) {
    const {width,height,chromaWidth,chromaHeight} = frame.format;
    if (width < 1 || height < 1 || width*height > 3840*2160 || chromaWidth !== Math.ceil(width/2) || chromaHeight !== Math.ceil(height/2)) throw new Error('Unsupported remote frame dimensions');
    this.canvas.width = width; this.canvas.height = height;
    const context = this.canvas.getContext('2d')!;
    const image = context.createImageData(width, height);
    for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
      const Y = frame.y.bytes[y*frame.y.stride+x]-16;
      const U = frame.u.bytes[(y>>1)*frame.u.stride+(x>>1)]-128;
      const V = frame.v.bytes[(y>>1)*frame.v.stride+(x>>1)]-128;
      const p = 4*(y*width+x);
      image.data[p] = (298*Y+409*V+128)>>8;
      image.data[p+1] = (298*Y-100*U-208*V+128)>>8;
      image.data[p+2] = (298*Y+516*U+128)>>8;
      image.data[p+3] = 255;
    }
    context.putImageData(image, 0, 0);
  }

  close() {
    this.stopped = true;
    this.pending?.reject(new Error('Remote session ended')); this.pending = undefined;
    if (this.native?.state !== 'closed') this.native?.close();
    this.software?.close();
  }
}
