# RustDesk Access Gateway — first v0.1 milestone

임의의 PC에서 프로그램 설치 없이 브라우저로 자신의 PC에 접근하기 위한 단일 사용자 Gateway입니다. 로그인과 원격 접근 권한을 분리하고, 각 PC 접속마다 Passkey 확인을 거쳐 최대 15분 동안만 유효한 세션을 발급합니다.

PC방 PC에서 Afterplay Benchmark가 GPU/CPU를 사용하는 동안 같은 PC의 브라우저로 Main PC를 제어하는 사용 사례를 목표로 합니다. 벤치마크와 원격 PC 작업은 각각의 PC에서 실행됩니다.

**현재 구현은 인증·세션·연결 정책 기반입니다. 실제 RustDesk 화면/입력 클라이언트는 아직 포함되어 있지 않으며, v0.1의 전체 성공 기준을 달성한 상태가 아닙니다.** 기본 설정에서는 원격 WebSocket 프록시와 Connect 버튼을 비활성화합니다. 테스트는 실제 WebAuthn 서명과 로컬 WebSocket upstream을 사용하지만 실제 RustDesk Host의 화면 전송을 검증하지는 않습니다.

## 구현된 기능

- 소유자 최초 Passkey 등록, discoverable 로그인, 필수 User Verification.
- 브라우저의 휴대폰 인증을 유도하는 `hybrid` 힌트. QR 코드는 브라우저/OS가 표시합니다.
- HttpOnly / SameSite=Strict / production Secure 세션 쿠키. refresh token, localStorage 인증 토큰, 장기 로그인 없음.
- PC별 Passkey 재확인 → 60초 이내 한 번만 사용할 수 있는 PC 접근 승인 → 최대 15분 Remote Access Session.
- SQLite 장치, Passkey credential/counter, 원격 세션, Audit Log 저장.
- 장치 목록과 Online / Offline / Unknown. 인증된 Host heartbeat를 받은 경우에만 Online, 45초 후 Offline.
- 소유자·PC·권한·상태·만료·revoke를 검증하는 WebSocket 진입점.
- 신호 메시지의 대상 RustDesk ID 제한, relay 강제, ICE/직접 주소 제거, 다른 연결 유형 거절.
- 승인된 signaling에서 얻은 UUID를 세션/PC에 묶어 한 번만 사용하는 Relay 연결 권한.
- 기존 양방향 WebSocket을 TTL, 수동 종료, 로그아웃, 전체 종료 시 강제 종료.
- 재시작 시 이전 활성 세션 폐기. 자동 연장 없음.
- Rate limit, 정확한 Origin 검사, CSP, 기본 Clipboard/파일 전송 차단 정책.
- React 포털, 남은 시간/경고/전체화면/종료 UI와 로컬 웹 어댑터 인터페이스.

## 로컬 실행

Go 1.27, Node.js 22가 개발 환경에 필요합니다. 접속하는 최종 사용자 PC에는 이 도구들이 필요하지 않습니다.

```powershell
cd D:\Developments\Projects\rustdesk\gateway\web
npm ci
npm run build
cd ..
Copy-Item config.example.json config.json

# 신뢰할 수 있는 개발 PC에서 최초 등록용 토큰을 생성합니다.
$taskBootstrap = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($taskBootstrap)
$env:RD_BOOTSTRAP_TOKEN = [Convert]::ToBase64String($taskBootstrap)
go run ./cmd/gateway -config config.json
```

`http://localhost:8080`을 열고 신뢰할 수 있는 기기에서 최초 소유자 설정을 진행합니다. 토큰은 다른 터미널로 전달하거나 안전하게 조회하여 직접 입력하세요. 토큰을 소스, URL, 로그에 기록하지 마세요. 소유자 Passkey가 한 개 등록되면 bootstrap 엔드포인트는 자동으로 거절합니다. 이후 `RD_BOOTSTRAP_TOKEN`을 제거하고 재시작할 수 있습니다. 추가 Passkey/복구 기능은 아직 없습니다.

실제 휴대폰 등록과 로그인은 동일한 production RP 도메인에서 HTTPS로 검증해야 합니다. localhost 데모만으로 휴대폰 cross-device 인증이 검증되지는 않습니다. 브라우저·OS·휴대폰과 BLE 근접성 지원에 따라 QR 인증 지원이 달라질 수 있으므로 Chrome/Edge/Firefox 각각 실기기 검증이 필요합니다. 임의의 PC가 WebAuthn을 지원한다는 사실만으로 QR 인증까지 보장되지는 않습니다.

브라우저 종료 시 `pagehide`에서 로그아웃/종료를 best effort로 요청합니다. 브라우저 강제 종료·네트워크 단절·세션 쿠키 복원은 웹 앱에서 완벽하게 감지할 수 없습니다. 서버가 강제하는 15분 상한은 그 경우에도 유지됩니다. UI와 쿠키에 장기 인증정보를 저장하지 않지만, 공용 PC 자체가 감염되어 있으면 화면과 입력을 보호할 수 없습니다.

## API 흐름

1. `POST /api/auth/passkey/challenge` — `{"purpose":"login"}`.
2. 브라우저 `navigator.credentials.get` → `POST /api/auth/passkey/verify`.
3. `GET /api/devices`.
4. `POST /api/auth/passkey/challenge` — `{"purpose":"connect","device_id":"main-pc"}`.
5. 새로운 WebAuthn assertion → `POST /api/auth/passkey/verify`.
6. `POST /api/devices/main-pc/sessions`.
7. `GET /api/sessions/{id}/connection`으로 승인된 연결 설정 조회.
8. 같은 origin의 `/ws/remote/{id}/id`, `/ws/remote/{id}/relay`로 연결.
9. `DELETE /api/sessions/{id}` 또는 `DELETE /api/sessions`로 종료.

상태 변경 API는 설정된 origin의 `Origin` 헤더가 필요합니다. 세션 ID와 URL만 알아서는 연결할 수 없습니다. 해당 세션을 생성한 브라우저의 활성 로그인도 필요합니다. grant가 소비되면 같은 로그인으로 세션을 재발급할 수 없으며 Passkey 재확인이 필요합니다. MVP 연장은 기존 세션을 종료하고 새로 인증하는 흐름입니다.

`POST /api/agent/devices/{id}/heartbeat`는 `Authorization: Bearer <device-token>`으로 보호됩니다. `heartbeat_token_env`에 지정한 환경 변수에 32자 이상의 별도 Host 비밀을 설정합니다. 브라우저에 제공되지 않는 credential입니다. Host가 실제 RustDesk 준비 상태를 확인한 뒤 15초마다 호출해야 하며, **그 상태를 확인/보고하는 Host Agent는 아직 구현하지 않았습니다.**

Rate limit은 IP별 1분당 auth 20회, session 60회, connect 30회, 기타 API 180회입니다. 신뢰 프록시 CIDR을 지정한 경우에만 Caddy가 덮어쓴 `X-Real-IP`를 읽습니다. 다른 요청의 forwarding 헤더는 무시합니다.

## 배포 기반

`deploy/compose.yaml`은 Caddy의 80/443만 publish하며 Gateway/hbbs/hbbr 포트를 외부에 공개하지 않습니다. RustDesk는 `internal: true` 네트워크에 두고 `ALWAYS_USE_RELAY=Y`로 설정합니다. 아래는 배포 준비 명령이며 이 변경으로 인터넷 서비스가 배포되지는 않았습니다.

```powershell
cd deploy
Copy-Item config.production.example.json config.json
# origin, 장치 ID, server_key, 비밀 환경 변수와 실제 도메인을 준비합니다.
$env:REMOTE_DOMAIN = 'remote.example.com'
docker compose config --quiet
docker compose up --build -d
```

Compose의 사설 Docker 네트워크만으로 다른 네트워크에 있는 Host가 자동으로 연결되지는 않습니다. 신뢰된 Host의 private routing/격리된 host network 또는 **Host 측** outbound 인증 터널이 필요합니다. Host 터널은 후속 작업이며 이를 해결하려고 21115–21119를 인터넷에 publish하면 핵심 요구사항을 위반합니다. 최종 접속 PC에 VPN/Agent 설치를 요구하지 않는 원칙은 유지합니다.

실제 Host에서는 public RustDesk 서버 fallback, direct IP access, LAN discovery, P2P 경로를 차단해야 합니다. Host 방화벽은 허가된 사설 RustDesk 경로만 허용하도록 구성합니다. `direct-server=N`, `enable-lan-discovery=N`, `enable-clipboard=N`, `enable-file-transfer=N`, `enable-terminal=N` 등의 권한을 Host에서도 강제해야 합니다. 암호화된 Relay payload의 Clipboard나 파일 메시지는 Gateway에서 읽을 수 없으므로 UI 토글만으로 정책을 보장할 수 없습니다. 현재 Clipboard 활성화는 제공하지 않습니다.

Gateway의 capability를 활성화하려면 검토된 로컬 웹 클라이언트의 `adapter.js`가 필요합니다. 단순히 `enable_rustdesk_proxy=true`로 바꾸는 것만으로 화면 제어가 구현되는 것은 아닙니다. 현재 필터는 pinned protobuf의 plaintext OSS signaling만 허용하고 알 수 없는 메시지/암호화된 signaling/ICE를 거절합니다. 실제 RustDesk 버전과 호환성을 확인하기 전까지 기본 비활성 상태를 유지하세요.

## 검증

```powershell
go test ./...
go vet ./...
cd web
npm run build
```

서명된 P-256 WebAuthn 등록/로그인, UV 누락, 변조, replay, PC별 grant와 일회성 소비, URL 유출/Origin/다른 PC 거절, ICE/파일 연결 거절, Relay ticket 재사용 거절, 이미 열린 idle 연결의 종료, 재시작 폐기를 검증합니다. GitHub CI는 Linux에서 `go test -race`도 실행하도록 구성했습니다. 로컬 Windows에는 CGo C 컴파일러가 없어 race 검사를 실행하지 못했습니다. Docker Compose 설정 문법은 확인했지만 로컬 Docker 엔진이 꺼져 있어 컨테이너 빌드는 검증하지 못했습니다.

`govulncheck`는 실제 호출하는 코드/패키지에서 알려진 취약점을 찾지 않았습니다. 간접 의존성 `golang.org/x/crypto`의 사용하지 않는 `openpgp` 패키지에 대해 `GO-2026-5932` 모듈 경고는 표시됩니다. 배포되는 React 의존성의 `npm audit --omit=dev`도 통과했습니다.

## 다음 단계와 성공 조건

1. [공개 웹 클라이언트 복원 메모](docs/web-client.md)에 따라 소스·codec 자산·라이선스를 확인하고 자체 포털 어댑터 구현.
2. 원격 Host의 격리 경로와 준비 상태 heartbeat Agent 구현. Host 인증과 Clipboard/파일 권한 강제.
3. 실제 Windows Host → 브라우저 화면, 키보드, 마우스, 전체화면을 검증.
4. 새 Windows PC의 Chrome/Edge/Firefox와 휴대폰 Passkey로 설치 없이 접속하고, 약 5초 내 화면 표시와 15분 만료 시 강제 종료를 측정.

휴대폰 접속 알림, TOTP, 추가 credential/복구, 관리자 Console, 다중 사용자/RBAC, 파일 전송, Clipboard opt-in, SSH, 녹화, 공유/초대 링크, 모바일 전용 UI는 후속 범위입니다. 알림을 발송하는 외부 서비스는 아직 연결하지 않았습니다.

변경 범위는 신규 `gateway/` 모듈과 신규 Gateway CI 워크플로입니다. 기존 RustDesk 실행 경로와 서브모듈 commit은 변경하지 않았습니다.

## 확인한 원본 자료

- [RustDesk 원본](https://github.com/rustdesk/rustdesk/tree/a7f2260203befb7e9c70b585219f0f0b5ca57703): fork 기준.
- [RustDesk self-host](https://rustdesk.com/docs/en/self-host/): ID/relay와 WebSocket 포트.
- [공식 웹 클라이언트 안내](https://rustdesk.com/blog/rustdesk-web-client-v2-preview/): 현재 hosted/self-hosted 경로.
- [Host advanced settings](https://rustdesk.com/docs/en/self-host/client-configuration/advanced-settings/): Host 권한과 direct access.
- [WebAuthn](https://www.w3.org/TR/webauthn-3/), [go-webauthn](https://github.com/go-webauthn/webauthn).

상위 저장소의 `LICENCE`(AGPL-3.0)가 적용됩니다.
