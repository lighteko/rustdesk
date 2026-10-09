export type ConnectionConfig = {
  session_id: string; device_id: string; peer_id: string; server_key: string;
  id_url: string; relay_url: string; expires_at: string;
  clipboard: false; file_transfer: false;
};

export type RemoteController = {disconnect(): void | Promise<void>};
export type RustDeskAdapter = {
  mount(element: HTMLElement, config: ConnectionConfig, signal: AbortSignal): Promise<RemoteController>;
};

export async function loadAdapter(): Promise<RustDeskAdapter> {
  // A locally supplied, reviewed browser client is deliberately required.
  // The upstream fork does not contain a distributable Flutter web client.
  const moduleURL = '/client/adapter.js';
  return import(/* @vite-ignore */ moduleURL);
}
