import {useEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {api, authenticate, registerPasskey} from './passkey';
import {ConnectionConfig, loadAdapter, RemoteController} from './adapter';
import './style.css';

type Device = {id: string; name: string; os: string; status: 'Online'|'Offline'|'Unknown'; last_seen_at: string|null; current_sessions: string[]};
type Session = {session_id: string; device_id: string; expires_at: string; status: string};
type Capabilities = {remote_desktop: boolean};

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [session, setSession] = useState<Session|null>(null);
  const [now, setNow] = useState(Date.now());
  const [token, setToken] = useState('');
  const [setup, setSetup] = useState(false);
  const screen = useRef<HTMLDivElement>(null);
  const controller = useRef<RemoteController|null>(null);
  const connecting = useRef<AbortController|null>(null);

  async function stopLocal() {
    connecting.current?.abort(); connecting.current = null;
    const current = controller.current; controller.current = null;
    try {if (current) await current.disconnect();}
    finally {screen.current?.replaceChildren();}
  }

  async function refresh() {
    await api('/api/me');
    const [list, capabilities] = await Promise.all([api<Device[]>('/api/devices'), api<Capabilities>('/api/capabilities')]);
    setDevices(list); setReady(capabilities.remote_desktop); setAuthenticated(true);
  }

  useEffect(() => {
    void refresh().catch(() => setAuthenticated(false));
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {window.clearInterval(tick); void stopLocal();};
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    const timer = window.setInterval(() => {
      void refresh().catch(() => {void stopLocal(); setSession(null); setAuthenticated(false); setMessage('인증이 만료되었습니다. 다시 인증해 주세요.');});
    }, 10000);
    return () => window.clearInterval(timer);
  }, [authenticated]);

  useEffect(() => {
    if (!session) return;
    if (now >= Date.parse(session.expires_at)) {
      void stopLocal(); setSession(null); setMessage('원격 세션이 만료되었습니다. 다시 Passkey로 인증해 주세요.');
    }
  }, [now, session]);

  useEffect(() => {
    if (!session) return;
    const timer = window.setInterval(() => {
      void api<Session>(`/api/sessions/${session.session_id}`).then(value => {
        if (value.status !== 'ACTIVE') {void stopLocal(); setSession(null); setMessage('원격 세션이 종료되었습니다.');}
      }).catch(() => {void stopLocal(); setSession(null); setMessage('세션을 확인할 수 없어 연결을 종료했습니다.');});
    }, 2000);
    return () => window.clearInterval(timer);
  }, [session?.session_id]);

  useEffect(() => {
    const id = session?.session_id;
    const cleanup = () => {
      connecting.current?.abort(); void controller.current?.disconnect();
      if (id) void fetch(`/api/sessions/${id}`, {method:'DELETE', credentials:'same-origin', keepalive:true}).catch(() => {});
      void fetch('/api/logout', {method:'POST', credentials:'same-origin', keepalive:true}).catch(() => {});
    };
    window.addEventListener('pagehide', cleanup);
    return () => window.removeEventListener('pagehide', cleanup);
  }, [session?.session_id]);

  async function run(action: () => Promise<void>) {
    setBusy(true); setMessage('');
    try {await action();} catch (error) {setMessage(error instanceof Error ? error.message : '요청을 완료하지 못했습니다.');}
    finally {setBusy(false);}
  }

  async function connect(device: Device) {
    await authenticate(device.id);
    const next = await api<Session>(`/api/devices/${device.id}/sessions`, {method:'POST'});
    setSession({...next,status:'ACTIVE'});
    try {
      const config = await api<ConnectionConfig>(`/api/sessions/${next.session_id}/connection`);
      const adapter = await loadAdapter();
      if (Date.now() >= Date.parse(next.expires_at)) throw new Error('원격 세션이 만료되었습니다. 다시 인증해 주세요.');
      const abort = new AbortController(); connecting.current = abort;
      await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
      if (!screen.current) throw new Error('원격 화면 영역을 준비할 수 없습니다.');
      const remote = await adapter.mount(screen.current, config, abort.signal);
      if (abort.signal.aborted) {await remote.disconnect(); return;}
      controller.current = remote;
    } catch (error) {
      await stopLocal(); setSession(null);
      await api(`/api/sessions/${next.session_id}`, {method:'DELETE'}).catch(() => {});
      throw error;
    }
  }

  const remaining = session ? Math.max(0, Math.ceil((Date.parse(session.expires_at)-now)/1000)) : 0;
  const warning = remaining <= 30 ? '30초 이하 남음' : remaining <= 60 ? '1분 이하 남음' : remaining <= 300 ? '5분 이하 남음' : '';
  const current = devices.find(d => d.id === session?.device_id);

  return <main>
    <header><div><span className="eyebrow">PRIVATE ACCESS GATEWAY</span><h1>내 PC에 안전하게 접속</h1></div>{authenticated && <button disabled={busy} onClick={() => void run(async () => {await api('/api/logout',{method:'POST'}); await stopLocal(); setSession(null); setAuthenticated(false);})}>로그아웃</button>}</header>
    {message && <p className="message" role="alert">{message}</p>}
    {!authenticated ? <section className="login"><h2>휴대폰 Passkey로 본인 확인</h2><p>브라우저 인증 창에서 ‘다른 기기’를 선택한 뒤 QR 코드를 휴대폰으로 스캔해 주세요.</p><p className="muted">QR 코드와 생체 인증은 브라우저가 제공합니다. 이 PC에 장기 인증정보를 저장하지 않습니다.</p><button className="primary" disabled={busy} onClick={() => void run(async () => {await authenticate(); await refresh();})}>{busy ? '인증 중…' : 'Verify Identity'}</button><button className="link" onClick={() => setSetup(!setup)}>최초 소유자 설정</button>{setup && <div className="setup"><p>소유자의 신뢰할 수 있는 기기에서만 최초 Passkey를 등록하세요.</p><input aria-label="일회성 초기 설정 토큰" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} placeholder="일회성 초기 설정 토큰"/><button disabled={busy || !token} onClick={() => void run(async () => {try {await registerPasskey(token); setSetup(false); setMessage('Passkey 등록 완료. 이제 인증할 수 있습니다.');} finally {setToken('');}})}>Passkey 등록</button></div>}</section> : <>
      {!ready && <p className="notice">Gateway 인증과 세션 API가 준비되었습니다. RustDesk 브라우저 어댑터가 아직 설치되지 않아 화면 제어는 활성화되지 않았습니다.</p>}
      {session ? <section className="remote"><div className="toolbar"><strong>{current?.name || session.device_id}</strong><span role="timer">남은 시간 {String(Math.floor(remaining/60)).padStart(2,'0')}:{String(remaining%60).padStart(2,'0')}</span><span className="warning" aria-live="polite">{warning}</span><button onClick={() => void screen.current?.parentElement?.requestFullscreen().catch(error => setMessage(error.message))}>전체화면</button><button disabled={busy} onClick={() => void run(async () => {await api(`/api/sessions/${session.session_id}`,{method:'DELETE'}); await stopLocal(); setSession(null); await refresh();})}>End Session</button></div><div ref={screen} className="screen"/><p className="muted">Clipboard OFF · 파일 전송 OFF · 자동 연장 없음</p></section> : <section><h2>My Devices</h2><div className="devices">{devices.map(device => <article key={device.id}><div className="pc-icon" aria-hidden>▣</div><h3>{device.name}</h3><p className="muted">{device.os}</p><p className={`status ${device.status.toLowerCase()}`}><span>●</span> {device.status}</p><p className="muted">마지막 확인: {device.last_seen_at ? new Date(device.last_seen_at).toLocaleString() : '상태 수신 대기'}</p><button className="primary" disabled={busy || !ready || device.status === 'Offline'} onClick={() => void run(() => connect(device))}>Connect · 15분</button></article>)}</div><p className="muted">접속할 때마다 Passkey를 다시 확인합니다. 세션을 연장하려면 종료 후 새로 인증하세요.</p></section>}
      <footer><span>공용 PC에는 장기 인증정보를 저장하지 않습니다.</span><button className="danger" disabled={busy} onClick={() => void run(async () => {await api('/api/sessions',{method:'DELETE'}); await stopLocal(); setSession(null); await refresh(); setMessage('모든 원격 세션을 종료했습니다.');})}>KILL ALL REMOTE SESSIONS</button></footer>
    </>}
  </main>;
}

createRoot(document.getElementById('root')!).render(<App/>);
