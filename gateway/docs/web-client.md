# 공개 RustDesk 웹 클라이언트 복원 작업

현재 fork 기준 `a7f2260203befb7e9c70b585219f0f0b5ca57703`에는 `flutter/lib/web/`의 Dart bridge/model 코드가 남아 있지만 `flutter/web/`의 JavaScript transport/build/codec 자산은 포함되어 있지 않습니다. 루트 `.gitignore`도 `flutter/web/`를 제외합니다. 따라서 최신 master만 checkout해서 완성된 웹 클라이언트를 빌드할 수 있다고 가정하지 않습니다.

원본 Git 이력에서 확인한 복원 후보:

- `41a20b50e` (`2024-06-22`, `split web js to v1 and v2`): 기존 transport 소스를 v1 경로로 이동.
- `5faf0ad3c^`의 `flutter/web/v1/js/src/connection.ts`, `websock.ts`, `codec.js`, `common.ts`, `gen_js_from_hbb.py`, `package.json`, `vite.config.js`, `yarn.lock`.
- 당시 `flutter/web/v1/README.md`와 codec 관련 외부 자산/빌드 도구 요구사항을 함께 확인해야 합니다.

공식 [V2 안내](https://rustdesk.com/blog/rustdesk-web-client-v2-preview/)는 공개 hosted client 및 Server Pro 자체 호스팅 경로를 설명합니다. 이 변경은 Pro 계약이나 배포 권한을 가정하지 않으며 타 사이트의 prebuilt V2 번들을 복사하지 않습니다. 역사적 v1 소스의 공개 여부와 현재 V2 제품의 배포 방식은 별개입니다.

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

## 다음 작업에서 확인할 것

- 공개 v1 transport와 현재 `hbb_common`/Host의 protocol/key exchange 호환성.
- VP8/VP9/AV1 decoder/WASM 자산의 출처, 라이선스와 재현 가능한 빌드.
- Flutter 전체 UI 없이 화면/입력을 React 포털에 연결할 수 있는 최소 경로.
- 현재 Gateway의 엄격한 framing과 response URL을 정확히 사용하는 수정. generic reverse proxy로 우회하지 않음.
- 실제 Host 비밀번호 또는 acceptance 정책을 짧은 세션 권한과 연결하는 방식.
- Host 외부 경로 봉쇄와 TTL 종료가 암호화된 데이터 연결까지 닫는 실기기 테스트.

화면 표시가 없는 fallback canvas, echo endpoint 또는 hosted-client iframe을 실제 원격 제어 성공으로 처리하지 않습니다. 현재 어댑터는 계약만 존재하며 가짜 원격 화면 구현은 추가하지 않았습니다.
