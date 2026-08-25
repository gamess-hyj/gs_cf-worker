# 게임세상 Cloudflare Worker 서비스 점검 안내 & 헬스체크 시스템

게임세상(Gamess) 서비스 점검 시 방문자에게 정기 점검 안내를 제공하고, 주요 서비스 도메인의 실시간 헬스체크 및 관리자 설정 기능을 제공하는 Cloudflare Worker 프로젝트입니다.

---

## 🌟 주요 기능 (Features)

1. **독립형 서비스 점검 안내 페이지 (`/`)**
   - **서버 다운 세이프티**: 메인 서버(`www.gamess.co.kr`)가 100% 다운되더라도 로고 및 페이지가 정상 표시되도록 내부에 Base64 Data URI 및 `/logo.png` 독립 라우트 포함.
   - **상태 및 시간 안내**: 점검 상태 (진행 중 / 예정 / 완료), 점검 일시 (시작~종료), 실시간 남은시간 카운트다운 타이머 제공.
   - **Modern Dark & Glassmorphism Design**: 게임세상 브랜드 컬러 및 동적 UI 적용.

2. **주요 도메인 헬스체크 모니터링 (`/api/health`)**
   - 아래 3개 서비스 도메인에 대한 Worker 백엔드 실시간 헬스체크 수행:
     - `www.gamess.co.kr` (메인 포털)
     - `play.gamess.co.kr` (게임 서비스)
     - `emul.gamess.co.kr` (에뮬레이터 서비스)
   - HTTP Status 및 Latency (ms) 측정 결과 UI 제공.

3. **관리자 대시보드 (`/admin`)**
   - **보안 로그인**: `ADMIN_KEY` 기반 세션 인증 및 쿠키 관리.
   - **실시간 수정**: 점검 상태, 안내 제목, 점검 시간 범위, 세부 내용, 영향 받는 서비스 목록, 연락처를 UI에서 수정.
   - **Cloudflare KV 연동**: `MAINTENANCE_KV`를 통해 수정 사항이 즉시 영구 저장 및 배포 반영 (KV 미설정 시 메모리 Fallback 지원).

---

## 🚀 프로젝트 구조 (Project Structure)

```text
gs_cf-worker/
├── package.json         # npm 설정 및 Wrangler CLI 스크립트
├── wrangler.toml        # Cloudflare Worker 및 KV Namespace 구성 파일
├── src/
│   ├── index.js         # Cloudflare Worker 백엔드 & HTML 렌더링 & API 핸들러
│   └── logo.js          # 백엔드 독립 동작용 로고 Base64 데이터
└── README.md            # 사용 및 배포 설명서
```

---

## 🛠️ 개발 및 실행 방법 (Local Development)

### 1. 의존성 설치
```bash
npm install
```

### 2. 로컬 개발 서버 실행
```bash
npm run dev
```
로컬 테스트 실행 후 브라우저에서 아래 경로를 확인하실 수 있습니다:
- Public Notice Page: `http://localhost:8787/`
- Admin Dashboard: `http://localhost:8787/admin` (기본 비밀번호: `gamess2026!`)
- Health Check API: `http://localhost:8787/api/health`

---

## ☁️ Cloudflare 배포 가이드 (Deployment)

### 1. KV Namespace 생성 (선택 사항 - 데이터 영구 저장용)
```bash
npx wrangler kv:namespace create MAINTENANCE_KV
```
명령어 실행 후 출력되는 `id` 값을 `wrangler.toml`의 `id` 부분에 추가합니다:
```toml
[[kv_namespaces]]
binding = "MAINTENANCE_KV"
id = "your-kv-namespace-id"
```

### 2. 관리자 비밀번호 (ADMIN_KEY) 비밀값 설정
```bash
npx wrangler secret put ADMIN_KEY
```
*(원하는 관리자 비밀번호를 입력합니다. 설정하지 않을 경우 `wrangler.toml`의 `gamess2026!` 기본값이 적용됩니다.)*

### 3. Worker 배포
```bash
npm run deploy
```

---

## 🔐 보안 및 팁 (Security)
- XSS 방지를 위한 HTML 엔티티 이스케이프 및 Safe DOM handling (`textContent`) 구현.
- HTTP Security Headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`) 자동 적용.
- 관리자 쿠키는 `HttpOnly; SameSite=Lax; Secure` 속성으로 안전하게 관리됩니다.
