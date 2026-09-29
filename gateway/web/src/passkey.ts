function fromBase64(s: string): ArrayBuffer {
  const bytes = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  return bytes.buffer;
}

function toBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, { ...init, credentials: 'same-origin', cache: 'no-store', headers: {'Content-Type': 'application/json', ...init.headers} });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${response.status}`);
  }
  return response.status === 204 ? undefined as T : response.json();
}

export async function authenticate(deviceId?: string) {
  if (!window.isSecureContext || !window.PublicKeyCredential) throw new Error('HTTPS와 WebAuthn을 지원하는 브라우저가 필요합니다.');
  const {publicKey} = await api<{publicKey: Record<string, unknown>}>('/api/auth/passkey/challenge', {
    method: 'POST', body: JSON.stringify({purpose: deviceId ? 'connect' : 'login', device_id: deviceId || ''}),
  });
  const options = {...publicKey, challenge: fromBase64(publicKey.challenge as string)} as PublicKeyCredentialRequestOptions;
  if (options.allowCredentials) options.allowCredentials = options.allowCredentials.map(c => ({...c, id: fromBase64(c.id as unknown as string)}));
  const credential = await navigator.credentials.get({publicKey: options}) as PublicKeyCredential | null;
  if (!credential) throw new Error('Passkey 인증이 취소되었습니다.');
  const response = credential.response as AuthenticatorAssertionResponse;
  await api('/api/auth/passkey/verify', {method: 'POST', body: JSON.stringify({
    id: credential.id, rawId: toBase64(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {clientDataJSON: toBase64(response.clientDataJSON), authenticatorData: toBase64(response.authenticatorData), signature: toBase64(response.signature), userHandle: response.userHandle ? toBase64(response.userHandle) : null},
  })});
}

export async function registerPasskey(token: string) {
  const headers = {'X-Bootstrap-Token': token};
  const {publicKey} = await api<{publicKey: Record<string, unknown>}>('/api/auth/passkey/register/challenge', {method: 'POST', headers});
  const user = publicKey.user as {id: string; name: string; displayName: string};
  const options = {...publicKey, challenge: fromBase64(publicKey.challenge as string), user: {...user, id: fromBase64(user.id)}} as PublicKeyCredentialCreationOptions;
  const credential = await navigator.credentials.create({publicKey: options}) as PublicKeyCredential | null;
  if (!credential) throw new Error('Passkey 등록이 취소되었습니다.');
  const response = credential.response as AuthenticatorAttestationResponse;
  await api('/api/auth/passkey/register/verify', {method: 'POST', headers, body: JSON.stringify({
    id: credential.id, rawId: toBase64(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {clientDataJSON: toBase64(response.clientDataJSON), attestationObject: toBase64(response.attestationObject), transports: response.getTransports()},
  })});
}
