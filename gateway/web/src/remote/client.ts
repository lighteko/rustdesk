import type {ConnectionConfig, RemoteController} from '../adapter';
import {hbb} from './generated/desktop';
import {gatewaySocketURL, RemoteSocket, securePeer} from './transport';
import {DesktopVideo} from './video';

const controls: Record<string,number> = {
  Alt:1, Backspace:2, CapsLock:3, Control:4, Delete:5, ArrowDown:6, End:7, Escape:8,
  F1:9, F10:10, F11:11, F12:12, F2:13, F3:14, F4:15, F5:16, F6:17, F7:18, F8:19, F9:20,
  Home:21, ArrowLeft:22, Meta:23, PageDown:25, PageUp:26, Enter:27, ArrowRight:28,
  Shift:29, ' ':30, Tab:31, ArrowUp:32,
};
const modifiers = (event:MouseEvent|KeyboardEvent) => [event.altKey ? 1:0, event.ctrlKey ? 4:0, event.metaKey ? 23:0, event.shiftKey ? 29:0].filter(Boolean);

export async function mount(element:HTMLElement, config:ConnectionConfig, signal:AbortSignal):Promise<RemoteController> {
  const expires = Date.parse(config.expires_at);
  if (signal.aborted || !Number.isFinite(expires) || expires <= Date.now() || expires-Date.now() > 15*60*1000 ||
      config.clipboard !== false || config.file_transfer !== false) throw new Error('Invalid remote access session');
  const idURL = gatewaySocketURL(config.id_url, 'id', config.session_id, config.device_id);
  const relayURL = gatewaySocketURL(config.relay_url, 'relay', config.session_id, config.device_id);
  const local = new AbortController();
  const canvas = document.createElement('canvas'); canvas.className = 'remote-canvas'; canvas.tabIndex = 0;
  canvas.setAttribute('aria-label','Remote desktop. Click to focus keyboard input.');
  const status = document.createElement('p'); status.className = 'remote-status'; status.setAttribute('role','status');
  status.textContent = 'Connecting through the Access Gateway…';
  element.replaceChildren(status, canvas);
  const video = new DesktopVideo(canvas);
  const sockets:RemoteSocket[] = [];
  let closed = false;
  let connected = false;
  let peerDisplay:hbb.IDisplayInfo|undefined;
  let keyboard = true;
  let relay:RemoteSocket|undefined;
  const heldKeys = new Map<string,hbb.IKeyEvent>();
  const heldButtons = new Set<number>();

  const releaseInput = () => {
    try {
      if (connected) {
        for (const value of heldKeys.values()) relay?.message({keyEvent:{...value, down:false, modifiers:[]}});
        for (const button of heldButtons) relay?.message({mouseEvent:{mask:2|(button<<3)}});
      }
    } finally {heldKeys.clear(); heldButtons.clear();}
  };
  const disconnect = (error?:Error) => {
    if (closed) return;
    try {releaseInput();} catch {heldKeys.clear(); heldButtons.clear();}
    closed = true; connected = false;
    clearTimeout(expiry); clearTimeout(startup);
    signal.removeEventListener('abort', abort);
    window.removeEventListener('blur', releaseInput);
    local.abort(); sockets.forEach(socket => socket.close()); video.close();
    canvas.width = 0; canvas.height = 0; canvas.remove();
    status.textContent = error?.message || 'Remote session ended.';
  };
  const abort = () => disconnect();
  const expiry = setTimeout(() => disconnect(new Error('Remote session expired. Authenticate again.')), expires-Date.now());
  const startup = setTimeout(() => disconnect(new Error('Remote PC approval or first frame timed out')), Math.min(120000, expires-Date.now()));
  signal.addEventListener('abort', abort, {once:true});
  window.addEventListener('blur', releaseInput);
  if (signal.aborted) abort();

  const send = (value:hbb.IMessage) => {
    if (!connected || closed || Date.now() >= expires) return;
    try {relay!.message(value);} catch(error) {disconnect(error instanceof Error ? error:new Error('Input transport failed'));}
  };
  const position = (event:MouseEvent) => {
    const bounds = canvas.getBoundingClientRect();
    return {x:Math.round((event.clientX-bounds.left)*canvas.width/bounds.width)+(peerDisplay?.x || 0),
      y:Math.round((event.clientY-bounds.top)*canvas.height/bounds.height)+(peerDisplay?.y || 0)};
  };
  canvas.addEventListener('contextmenu', event => event.preventDefault(), {signal:local.signal});
  canvas.addEventListener('pointermove', event => {
    if (canvas.width) send({mouseEvent:{...position(event), modifiers:modifiers(event)}});
  }, {signal:local.signal});
  const mouse = (event:PointerEvent, down:boolean) => {
    if (!canvas.width || !keyboard) return;
    const button = [1,4,2][event.button]; if (!button) return;
    event.preventDefault(); canvas.focus();
    if (down) {canvas.setPointerCapture(event.pointerId); heldButtons.add(button);} else {heldButtons.delete(button);}
    send({mouseEvent:{mask:(down ? 1:2)|(button<<3), ...position(event), modifiers:modifiers(event)}});
  };
  canvas.addEventListener('pointerdown', event => mouse(event,true), {signal:local.signal});
  canvas.addEventListener('pointerup', event => mouse(event,false), {signal:local.signal});
  canvas.addEventListener('pointercancel', releaseInput, {signal:local.signal});
  canvas.addEventListener('wheel', event => {
    event.preventDefault();
    if (keyboard) send({mouseEvent:{mask:3, x:-Math.sign(event.deltaX), y:-Math.sign(event.deltaY), modifiers:modifiers(event)}});
  }, {passive:false, signal:local.signal});
  const key = (event:KeyboardEvent, down:boolean) => {
    if (!connected || !keyboard || event.isComposing) return;
    const control = controls[event.key];
    const value:hbb.IKeyEvent = {down, modifiers:modifiers(event)};
    if (control) {value.controlKey = control; value.modifiers = value.modifiers!.filter(mod => mod !== control);}
    else if ([...event.key].length === 1) value.chr = event.key.codePointAt(0);
    else return;
    event.preventDefault();
    if (down) heldKeys.set(event.code,value); else {
      const pressed = heldKeys.get(event.code); if (pressed) Object.assign(value,pressed,{down:false,modifiers:modifiers(event)});
      heldKeys.delete(event.code);
    }
    send({keyEvent:value});
  };
  canvas.addEventListener('keydown', event => key(event,true), {signal:local.signal});
  canvas.addEventListener('keyup', event => key(event,false), {signal:local.signal});
  canvas.addEventListener('blur', releaseInput, {signal:local.signal});
  canvas.addEventListener('compositionend', event => {
    if (keyboard && event.data) send({keyEvent:{seq:event.data}});
  }, {signal:local.signal});

  const receive = async () => {
    while (!closed) {
      const packet = hbb.Message.decode(await relay!.next(90000));
      if (packet.hash) {
        status.textContent = 'Approve this connection in RustDesk on the remote PC.';
        relay!.message({loginRequest:{username:config.peer_id, myId:`gateway-${config.session_id}`, myName:'Access Gateway browser', myPlatform:'Web', version:'1.4.9', videoAckRequired:true,
          option:{disableAudio:2, disableClipboard:2, enableFileTransfer:1, showRemoteCursor:2,
            supportedDecoding:{abilityVp9:1, abilityVp8:1, prefer:1}, customFps:30}}});
      } else if (packet.loginResponse) {
        if (packet.loginResponse.error === 'No Password Access') {
          status.textContent = 'Approve this connection in RustDesk on the remote PC.';
          continue;
        }
        if (packet.loginResponse.error) throw new Error(`Remote PC authentication: ${packet.loginResponse.error}`);
        const peer = packet.loginResponse.peerInfo;
        peerDisplay = peer?.displays?.[peer.currentDisplay || 0];
        if (!peerDisplay || !peerDisplay.width || !peerDisplay.height) throw new Error('Remote PC has no available display');
        connected = true; status.textContent = 'Connected. Waiting for the remote screen…';
      } else if (packet.videoFrame) {
        if (!connected) throw new Error('Video received before remote PC authentication');
        await video.draw(packet.videoFrame);
        if (closed) return;
        relay!.message({misc:{videoReceived:true}});
        clearTimeout(startup); status.textContent = '';
      } else if (packet.testDelay && !packet.testDelay.fromClient) {
        relay!.message({testDelay:packet.testDelay});
      } else if (packet.misc?.closeReason) throw new Error(packet.misc.closeReason);
      else if (packet.misc?.permissionInfo?.permission === 0) {
        releaseInput(); keyboard = !!packet.misc.permissionInfo.enabled;
      } else if (packet.misc?.switchDisplay) {
        releaseInput(); peerDisplay = packet.misc.switchDisplay;
      }
      // Clipboard, file, audio, camera, terminal and unknown messages have no handler.
    }
  };

  try {
    const id = new RemoteSocket(idURL, local.signal, error => disconnect(error)); sockets.push(id);
    await id.opened;
    id.rendezvous({punchHoleRequest:{id:config.peer_id, natType:2, licenceKey:config.server_key, forceRelay:true, version:'1.4.9'}});
    const discovery = hbb.RendezvousMessage.decode(await id.next(10000));
    if (!discovery.relayResponse) throw new Error(discovery.punchHoleResponse?.otherFailure || `Remote PC unavailable (${discovery.punchHoleResponse?.failure ?? 'unknown'})`);
    const ticket = discovery.relayResponse;
    if (ticket.refuseReason || !ticket.uuid || !ticket.pk?.length) throw new Error(ticket.refuseReason || 'Remote PC did not provide a signed relay ticket');
    if (gatewaySocketURL(ticket.relayServer!, 'relay', config.session_id, config.device_id) !== relayURL) throw new Error('Untrusted relay destination');
    id.close();
    relay = new RemoteSocket(relayURL, local.signal, error => disconnect(error)); sockets.push(relay);
    await relay.opened;
    relay.rendezvous({requestRelay:{id:config.peer_id, uuid:ticket.uuid, secure:true, licenceKey:config.server_key}});
    await securePeer(relay, ticket.pk, config.server_key, config.peer_id);
    void receive().catch(error => disconnect(error instanceof Error ? error:new Error('Remote protocol failed')));
    return {disconnect:() => disconnect()};
  } catch(error) {disconnect(error instanceof Error ? error:new Error('Remote connection failed')); throw error;}
}
