# Hướng dẫn đọc code & test theo từng feature

Tài liệu này hướng dẫn từng bước cách **đọc hiểu code** và **kiểm thử thủ công** hai feature
chính của POC. Đọc lần lượt theo thứ tự — mỗi bước nêu rõ file/method cần xem và lệnh để chạy.

> Khởi động ứng dụng trước khi test: `mvn spring-boot:run` (mở <http://localhost:8080>).
> Chạy unit test: `mvn test`.

---

## 0. Bản đồ dự án

```
src/main/java/com/demo/authpoc
├── AuthPocApplication.java         ← entry point Spring Boot
├── config/
│   ├── AppProperties.java          ← bind YAML → record (jwt, oauth)
│   └── SecurityConfig.java         ← cấu hình Spring Security + filter chain
├── user/
│   ├── User.java                   ← record (id, username, password, roles)
│   └── UserService.java            ← in-memory user store, BCrypt
├── jwt/                            ← FEATURE 1
│   ├── AuthController.java         ← /api/auth/{login,refresh,logout} + /api/me
│   ├── JwtService.java             ← phát hành / xác thực JWT HS256
│   ├── JwtAuthenticationFilter.java← đọc Bearer token, set SecurityContext
│   ├── RefreshToken.java           ← record refresh token
│   ├── RefreshTokenService.java    ← rotation + reuse detection
│   └── dto/                        ← Login/Refresh/TokenResponse
├── oauth/                          ← FEATURE 2
│   ├── AuthorizationServerController.java ← /oauth/authorize + /oauth/token
│   ├── AuthorizationCode.java      ← record auth code
│   ├── AuthorizationCodeStore.java ← in-memory store, dùng 1 lần, TTL ngắn
│   ├── ClientDemoController.java   ← public client demo (/client/**)
│   ├── ClientRegistry.java         ← danh sách client đã đăng ký
│   ├── PkceUtils.java              ← verifier/challenge + verify constant-time
│   └── OAuthException.java
└── web/
    ├── HomeController.java         ← trang chủ
    └── ApiExceptionHandler.java    ← map exception → HTTP response

src/main/resources/
├── application.yml                 ← cấu hình issuer, TTL, client
└── templates/                      ← Thymeleaf views

src/test/java/com/demo/authpoc/
├── RefreshTokenRotationTest.java   ← test feature 1
└── PkceUtilsTest.java              ← test feature 2 (RFC 7636 vector)
```

**Người mới nên đọc theo thứ tự:** `AppProperties` → `SecurityConfig` → `UserService` → tới
feature muốn tìm hiểu (jwt hoặc oauth).

---

## 1. Feature 1 — JWT + Refresh Token Rotation

### 1.1 Đọc code theo thứ tự

| # | File | Cần chú ý |
|---|------|-----------|
| 1 | [application.yml:11-16](src/main/resources/application.yml) | `secret`, `access-token-ttl=5m`, `refresh-token-ttl=7d` |
| 2 | [AppProperties.java](src/main/java/com/demo/authpoc/config/AppProperties.java) | Record bind config |
| 3 | [JwtService.java](src/main/java/com/demo/authpoc/jwt/JwtService.java) | `issueAccessToken()` (line 32), `parseAndValidate()` (line 46) — chú ý HS256 + `requireIssuer` |
| 4 | [RefreshToken.java](src/main/java/com/demo/authpoc/jwt/RefreshToken.java) | Các field `familyId`, `used`, `revoked` |
| 5 | [RefreshTokenService.java](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) | `rotate()` (line 55) — đọc 4 nhánh check theo thứ tự: unknown → revoked → expired → **used (reuse!)** |
| 6 | [AuthController.java](src/main/java/com/demo/authpoc/jwt/AuthController.java) | Kết nối service vào HTTP endpoint |
| 7 | [JwtAuthenticationFilter.java](src/main/java/com/demo/authpoc/jwt/JwtAuthenticationFilter.java) | Đọc Bearer token → set `SecurityContext`. Lưu ý: filter này **permissive** — token sai không trả 401 ngay, để rule `authorizeHttpRequests` quyết định |
| 8 | [SecurityConfig.java](src/main/java/com/demo/authpoc/config/SecurityConfig.java) | Đăng ký filter vào filter chain |

### 1.2 Câu hỏi tự kiểm tra khi đọc

- Tại sao refresh token là **opaque** (chuỗi random) thay vì JWT? → Để có thể revoke tức thì.
- `familyId` để làm gì? → Liên kết mọi token rotation từ cùng 1 lần login; reuse → revoke cả family.
- Tại sao access token có TTL 5 phút? → Không revoke được giữa chừng, nên giữ ngắn.
- `JwtService.parseAndValidate` ném exception gì khi token sai? → `JwtException` (xem filter line 53).

### 1.3 Test thủ công bằng curl (golden path)

```bash
# 1. Login
LOGIN=$(curl -s localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"wonderland"}')
ACCESS=$(echo "$LOGIN"  | jq -r .accessToken)
REFRESH=$(echo "$LOGIN" | jq -r .refreshToken)

# 2. Gọi endpoint protected → 200
curl -s localhost:8080/api/me -H "Authorization: Bearer $ACCESS" | jq

# 3. Rotate refresh token → 200, nhận token mới
ROT=$(curl -s localhost:8080/api/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}")
NEW_REFRESH=$(echo "$ROT" | jq -r .refreshToken)
```

### 1.4 Test thủ công các case lỗi

| Case | Lệnh | Kỳ vọng |
|------|------|---------|
| Sai password | `curl localhost:8080/api/auth/login -H 'content-type: application/json' -d '{"username":"alice","password":"wrong"}'` | 401 + body lỗi |
| Token không có Bearer | `curl localhost:8080/api/me` | 401/403 |
| JWT bị sửa | `curl localhost:8080/api/me -H "Authorization: Bearer xxx.yyy.zzz"` | 401/403 |
| **Reuse refresh token cũ** | gọi `/refresh` với `$REFRESH` (đã dùng) | 401 `Refresh token reuse detected; family revoked` |
| **Token con cũng bị revoke** | gọi `/refresh` với `$NEW_REFRESH` ngay sau case trên | 401 `Refresh token revoked` |
| Logout | `curl -X POST localhost:8080/api/auth/logout -H 'content-type: application/json' -d "{\"refreshToken\":\"$NEW_REFRESH\"}"` | 204; lần refresh kế tiếp → 401 |

### 1.5 Test tự động

```bash
mvn test -Dtest=RefreshTokenRotationTest
```

File: [RefreshTokenRotationTest.java](src/test/java/com/demo/authpoc/RefreshTokenRotationTest.java)

- `rotationMintsNewTokenAndBurnsTheOld()` — verify happy path + reuse detection lan ra cả family.
- `unknownTokenIsRejected()` — verify token không tồn tại bị reject.

**Cách thêm test mới:** copy mẫu `newService()` (line 16) để có instance sạch, dùng
`assertThrows(RefreshTokenException.class, ...)` cho các case lỗi.

---

## 2. Feature 2 — OAuth 2.1 Authorization Code + PKCE

### 2.1 Đọc code theo thứ tự

| # | File | Cần chú ý |
|---|------|-----------|
| 1 | [application.yml:17-24](src/main/resources/application.yml) | `demo-client`, `redirectUris`, `requirePkce: true` |
| 2 | [ClientRegistry.java](src/main/java/com/demo/authpoc/oauth/ClientRegistry.java) | Lookup client theo id |
| 3 | [PkceUtils.java](src/main/java/com/demo/authpoc/oauth/PkceUtils.java) | `newCodeVerifier()`, `s256Challenge()`, **`verify()` dùng `MessageDigest.isEqual` (constant-time)** — chống timing attack |
| 4 | [AuthorizationCode.java](src/main/java/com/demo/authpoc/oauth/AuthorizationCode.java) | Record lưu `codeChallenge`, `codeChallengeMethod`, `consumed`, `expiresAt` |
| 5 | [AuthorizationCodeStore.java](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java) | `consume()` (line 41) — atomic: check `consumed`/`expired` → mark consumed |
| 6 | [AuthorizationServerController.java](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) | 3 endpoint: GET `/oauth/authorize` (form), POST `/oauth/authorize` (submit), POST `/oauth/token` (đổi code lấy token). Chú ý các check ở line 53-65 và line 117-131 |
| 7 | [ClientDemoController.java](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java) | Mô phỏng phía browser: tạo verifier+challenge+state, lưu session, callback đổi token |

### 2.2 Sơ đồ luồng (PKCE handshake)

```
Browser            DemoClient (/client)         AuthServer (/oauth)         ResourceServer (/api/me)
   │   GET /client/login        │                       │                              │
   │ ─────────────────────────► │                       │                              │
   │                            │ tạo verifier+challenge+state                         │
   │                            │ lưu vào HttpSession                                  │
   │ ◄─302 /oauth/authorize?... │                       │                              │
   │   với code_challenge=S256  │                       │                              │
   │ ──────────────────────────────────────────────────►│                              │
   │                            │                       │ render form login            │
   │ ◄────────────────────── login form ────────────────│                              │
   │   POST username+password   │                       │                              │
   │ ──────────────────────────────────────────────────►│                              │
   │                            │                       │ issue auth code (lưu kèm     │
   │                            │                       │   code_challenge)            │
   │ ◄─302 /client/callback?code=...&state=...          │                              │
   │   GET /client/callback     │                       │                              │
   │ ─────────────────────────► │                       │                              │
   │                            │ check state khớp session                             │
   │                            │ POST /oauth/token                                    │
   │                            │   code + code_verifier ───────►│                     │
   │                            │                       │ consume code (atomic, 1 lần) │
   │                            │                       │ verify S256(verifier)==      │
   │                            │                       │        stored challenge      │
   │                            │ ◄── access_token ─────│                              │
   │                            │ GET /api/me Bearer ...───────────────────────────────►
   │                            │ ◄── user info ───────────────────────────────────────
   │ ◄── render profile ────────│                       │                              │
```

### 2.3 Câu hỏi tự kiểm tra

- Tại sao PKCE cần thiết? → Public client không lưu được secret, PKCE chứng minh "đúng client đã khởi flow".
- Tại sao `S256` mà không phải `plain`? → `plain` để lộ verifier nếu authorize request bị intercept.
- Tại sao `verify()` dùng `MessageDigest.isEqual`? → Constant-time, chống timing attack.
- `state` để làm gì? → Chống CSRF; client check `state` trả về phải khớp với cái lưu trong session.
- Code dùng 1 lần — replay sẽ bị bắt ở đâu? → [AuthorizationCodeStore.java:44-48](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java).

### 2.4 Test thủ công qua trình duyệt (golden path)

1. Mở <http://localhost:8080>.
2. Click **Start PKCE flow** → tới `/client/login` → redirect sang `/oauth/authorize`.
3. Login `alice` / `wonderland`.
4. Trình duyệt redirect về `/client/callback?code=...&state=...`.
5. Trang profile hiển thị: `access_token`, payload `/api/me`, `verifier`, `code`.

### 2.5 Test thủ công qua curl (manual handshake)

**Bước 1 — tạo verifier + challenge:**
```bash
python3 -c "
import os, base64, hashlib
v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print('verifier ',v); print('challenge',c)
"
```

**Bước 2 — mở URL authorize trong browser, login, copy `code` từ URL callback:**
```
http://localhost:8080/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/client/callback&scope=USER&state=xyz&code_challenge=<CHALLENGE>&code_challenge_method=S256
```

**Bước 3 — đổi code lấy token:**
```bash
curl -s -X POST localhost:8080/oauth/token \
  -d grant_type=authorization_code \
  -d code=<CODE> \
  -d redirect_uri=http://localhost:8080/client/callback \
  -d client_id=demo-client \
  -d code_verifier=<VERIFIER> | jq
```

### 2.6 Test thủ công các case lỗi

| Case | Cách thử | Kỳ vọng |
|------|----------|---------|
| Sai `client_id` | đổi `client_id=foo` ở URL authorize | `invalid_request` |
| `redirect_uri` không đăng ký | đổi `redirect_uri=http://evil.com` | `invalid_request` |
| `code_challenge_method=plain` | đổi method ở URL authorize | `invalid_request` "only S256..." |
| Thiếu PKCE | bỏ `code_challenge` | `invalid_request` |
| Sai `code_verifier` | gửi verifier khác khi đổi token | `invalid_grant: PKCE verification failed` |
| **Replay code** | gọi `/oauth/token` 2 lần với cùng code | lần 2: `invalid_grant: code already used` |
| Code hết hạn | chờ > 60s rồi mới đổi | `invalid_grant: code expired` |
| Sai password | login với password sai trên form | `invalid_grant: bad credentials` |

### 2.7 Test tự động

```bash
mvn test -Dtest=PkceUtilsTest
```

File: [PkceUtilsTest.java](src/test/java/com/demo/authpoc/PkceUtilsTest.java)

- `rfc7636AppendixBVector()` — verify với **test vector chính thức trong RFC 7636 Appendix B**.
  Test này quan trọng vì nó chứng minh implementation đúng spec.
- `rejectsPlainMethod()` — verify method `plain` bị từ chối.
- `wrongVerifierFails()` — verifier sai → fail.

---

## 3. Tip mở rộng

### 3.1 Bật log chi tiết

`application.yml` đã set `com.demo.authpoc: DEBUG`. Khi test reuse detection, theo dõi log
`ERROR REUSE DETECTED on token family=... user=...` ở [RefreshTokenService.java:74](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java).

### 3.2 Debug nhanh JWT

Copy access token rồi paste vào <https://jwt.io> (chỉ paste **header.payload**, không paste signature trên app production thật). Xem `iss`, `sub`, `scope`, `exp`.

### 3.3 Reset state

POC dùng in-memory store → **restart app** là sạch hết: refresh token, auth code, session.

### 3.4 Viết thêm test integration

Hiện chỉ có unit test cho 2 service. Có thể thêm `@SpringBootTest` + `MockMvc` để test:
- Toàn bộ flow login → refresh → logout
- Replay auth code qua `/oauth/token`
- PKCE mismatch

### 3.5 Checklist khi thay đổi code

- Đổi `RefreshTokenService` → chạy lại `RefreshTokenRotationTest`.
- Đổi `PkceUtils` → chạy lại `PkceUtilsTest` (đặc biệt RFC vector).
- Đổi `SecurityConfig` → test thủ công lại `/api/me` với token hợp lệ và token sai.
- Đổi `AuthorizationServerController` → test thủ công full flow trên browser.
