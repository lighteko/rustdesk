# RustDesk 브라우저 어댑터의 출처와 검증 범위

현재 fork 기준 `a7f2260203befb7e9c70b585219f0f0b5ca57703`에는 `flutter/lib/web/`의 Dart bridge/model 코드가 남아 있지만 `flutter/web/`의 JavaScript transport/build/codec 자산은 포함되어 있지 않습니다. 루트 `.gitignore`도 `flutter/web/`를 제외합니다. 따라서 최신 master만 checkout해서 완성된 웹 클라이언트를 빌드할 수 있다고 가정하지 않습니다.

원본 Git 이력에서 확인한 복원 후보:

- `41a20b50e` (`2024-06-22`, `split web js to v1 and v2`): 기존 transport 소스를 v1 경로로 이동.
- `5faf0ad3c^`의 `flutter/web/v1/js/src/connection.ts`, `websock.ts`, `codec.js`, `common.ts`, `gen_js_from_hbb.py`, `package.json`, `vite.config.js`, `yarn.lock`.
- 당시 `flutter/web/v1/README.md`와 codec 관련 외부 자산/빌드 도구 요구사항을 함께 확인해야 합니다.

공식 [V2 안내](https://rustdesk.com/blog/rustdesk-web-client-v2-preview/)는 공개 hosted client 및 Server Pro 자체 호스팅 경로를 설명합니다. 이 변경은 Pro 계약이나 배포 권한을 가정하지 않으며 타 사이트의 prebuilt V2 번들을 복사하지 않습니다. 역사적 v1 소스의 공개 여부와 현재 V2 제품의 배포 방식은 별개입니다.

## 현재 어댑터

`gateway/web/protocol/desktop.proto`는 fork에 포함된 `libs/base/protos/message.proto`와 고정된 `libs/hbb_common/protos/rendezvous.proto`에서 브라우저가 사용하는 필드만 추린 wire subset입니다. 빌드 중 `protobufjs-cli`로 정적 ES module과 타입을 생성합니다. 브라우저 연결 코드와 VP8/VP9 디코더는 각각 `gateway/web/src/remote/`와 npm 잠금 파일에 고정된 `ogv` 1.9.0에서 빌드합니다. 기존 Flutter 웹 UI나 별도 hosted V2 번들은 포함하지 않습니다.

`npm run build`는 포털을 `gateway/web/dist`, 어댑터와 같은 origin의 codec 자산을 `gateway/client`에 생성합니다. Docker 이미지는 둘 다 복사합니다. 네트워크 연결은 `/ws/remote/{session_id}/id` 및 `/relay`만 사용하며 Host의 server-signed key와 peer-signed key를 검증한 뒤 secretbox로 암호화합니다. 화면은 WebCodecs VP8/VP9을 우선 사용하고 필요하면 로컬 OGV worker/WASM으로 디코딩합니다. 브라우저의 Clipboard, 파일, 오디오, terminal 기능은 구현하지 않았습니다. Host도 이를 차단해야 합니다.

`npm test`는 고정된 Gateway URL, 잘못된 Host 서명, 키 교환과 양방향 암호화, 패킷 replay 및 abort 정리를 검사합니다. 사설 RustDesk 서버와 MacBook **Host**를 쓴 시험에서는 암호화된 handshake와 Host connection manager 도착까지 확인했습니다. MacBook의 승인 창이 보이지 않아 화면/입력/종료는 검증하지 못했습니다. 제품 목표에 맞는 실기기 시험 방향은 MacBook **브라우저** → Windows Host입니다.

Host password를 브라우저에 저장하지 않기 위해 현재 어댑터는 Host의 click 승인 모드에 의존합니다. 무인 Main PC 접근에 필요한 session-bound Host 인증 broker가 구현되기 전까지 이 버전은 v0.1 완료가 아닙니다. Relay 연결은 승인된 RAS에 묶여 있지만, Gateway를 우회하는 Host 경로를 차단하는 운영 설정도 별도로 필요합니다.

## 어댑터 계약

`gateway/web/src/adapter.ts`의 인터페이스에 맞는 로컬 ES module을 `client_dir/adapter.js`로 제공합니다. 클라이언트는 `mount(element, config, signal)`을 export하고 `disconnect()`를 제공해야 합니다. 번들/worker/WASM 자산 역시 local same-origin에서 제공하며 외부 script, Firebase analytics, localStorage/sessionStorage 인증정보를 사용하지 않습니다.

`config`는 활성 Remote Access Session과 그 세션의 브라우저 소유자를 검사한 뒤에만 제공합니다. `peer_id`와 server public key는 RustDesk 프로토콜에 필요한 값이며 접근 credential이 아닙니다. 실제 접근은 HttpOnly 로그인 + 활성 Remote Access Session + PC-bound Relay ticket에 의존합니다.

필수 연결 정책:

1. ID discovery는 주어진 `id_url`, relay는 `relay_url`만 사용. 임의의 RustDesk 서버/ID 입력 UI를 제거.
2. `PunchHoleRequest`의 대상은 승인된 `peer_id`. Gateway가 `force_relay`를 강제하며 ICE/UDP/IPv6/UPnP 후보를 거절.
3. signaling이 받은 RelayResponse UUID를 relay의 첫 RequestRelay에 사용. UUID는 30초 또는 세션 만료 중 이른 시점까지, 한 번만 허용.
4. signaling encryption을 투명 통과시키지 않음. 추가 암호화 지원 시 Gateway가 타깃을 검증할 수 있는 broker/protocol integration을 별도 구현.
5. peer 간 암호화는 유지. Host 인증은 다음 단계에서 session-bound 방식으로 설계하며 영구 Host 비밀번호를 저장하는 UI를 도입하지 않음.
6. 화면 출력, 키보드/마우스, 전체화면과 disconnect만 노출. Clipboard/파일/terminal/tunnel은 Host 권한에서도 차단.
7. AbortSignal이나 서버 socket close를 받으면 decoder/worker/input listener와 모든 연결을 정리.

## 남은 검증과 구현

- Windows Host가 사설 server에만 등록되도록 설정하고 외부 직접 연결을 차단.
- Host의 click 승인/영구 비밀번호 대신 RAS와 연결된 일시 인증을 설계하고 구현.
- MacBook 브라우저에서 실제 VP8/VP9 화면, 입력, 전체화면, 세션 만료 종료를 실기기로 검증.
- Chrome/Edge/Firefox의 WebCodecs 또는 OGV fallback을 확인하고 Host 권한에서 Clipboard/파일 차단 검증.

화면 표시가 없는 fallback canvas, echo endpoint 또는 hosted-client iframe을 실제 원격 제어 성공으로 처리하지 않습니다.
