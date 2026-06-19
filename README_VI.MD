# auth-security-poc

Một ứng dụng Spring Boot 3 (Java 21) minh hoạ hai mô hình bảo mật xác thực:

1. **Xoay vòng JWT refresh token** kèm phát hiện tái sử dụng (refresh token dạng opaque lưu phía server).
2. **OAuth 2.1 Authorization Code flow + PKCE** (S256), kèm một public client demo chạy trong cùng tiến trình.

Mọi thứ đều lưu trong bộ nhớ (in-memory) nên POC khởi động sạch mỗi lần chạy. Tài khoản demo:

| Username | Password    | Roles       |
|----------|-------------|-------------|
| alice    | wonderland  | USER        |
| bob      | builder     | USER, ADMIN |

---

## Yêu cầu

- Java 21 (đã cài sẵn).
- Maven 3.9+ — cài bằng `brew install maven`.

## Chạy ứng dụng

```bash
cd /Users/pat/Documents/Code/Github/auth-security-poc
mvn spring-boot:run
```

Sau đó mở <http://localhost:8080>.

## Chạy test

```bash
mvn test
```

---

## Demo 1 — Xoay vòng JWT refresh token

JWT access token thời hạn ngắn (5 phút) đi kèm với refresh token opaque thời hạn dài (7 ngày).
Mỗi lần gọi `/refresh` sẽ xoay vòng refresh token: token được gửi lên bị đánh dấu **đã sử dụng**
và một token mới được phát hành trong cùng một **family** (họ). Nếu một token đã dùng được gửi
lại lần thứ hai, hệ thống coi đây là bằng chứng bị đánh cắp — toàn bộ family sẽ bị thu hồi.

### Thao tác từng bước

```bash
# 1. Đăng nhập.
LOGIN=$(curl -s localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"wonderland"}')
echo "$LOGIN" | jq

ACCESS=$(echo "$LOGIN"  | jq -r .accessToken)
REFRESH=$(echo "$LOGIN" | jq -r .refreshToken)

# 2. Gọi một endpoint được bảo vệ.
curl -s localhost:8080/api/me -H "Authorization: Bearer $ACCESS" | jq

# 3. Xoay vòng refresh token.
ROT=$(curl -s localhost:8080/api/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}")
echo "$ROT" | jq
NEW_REFRESH=$(echo "$ROT" | jq -r .refreshToken)

# 4. Thử dùng lại refresh token CŨ → cơ chế phát hiện tái sử dụng được kích hoạt,
#    và toàn bộ family bị thu hồi (nên $NEW_REFRESH cũng không còn dùng được).
curl -s -i localhost:8080/api/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"
# 401 invalid_grant — "Refresh token reuse detected; family revoked"

curl -s -i localhost:8080/api/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$NEW_REFRESH\"}"
# 401 invalid_grant — "Refresh token revoked"
```

### Token family là gì?

**Family** = tập hợp tất cả refresh token sinh ra từ **cùng một lần login**, liên kết qua
`familyId` (UUID). Đây là chìa khoá của cơ chế reuse detection.

```
Login (alice) ──► Family A (familyId = "fam-aaa")
                  ├── RT₁ [used]   ──► rotate
                  ├── RT₂ [used]   ──► rotate
                  ├── RT₃ [used]   ──► rotate
                  └── RT₄ [active]  ← user đang giữ
```

Quy tắc:

- **Login lần đầu** → sinh `familyId` mới (xem `issueNewFamily()` ở
  [RefreshTokenService.java:44-46](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java)).
- **Mỗi lần rotate** → token mới giữ nguyên `familyId` của cha
  ([RefreshTokenService.java:80-81](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java)).
- **Phát hiện reuse** (token đã `used` lại bị gửi lên) → revoke **toàn bộ family**, không
  chỉ token bị reuse ([RefreshTokenService.java:72-78](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java)).

**Tại sao revoke cả family thay vì chỉ token bị reuse?** Vì nếu một token đã used lại xuất
hiện, nghĩa là có **2 bên** đang cùng giữ refresh token — không thể biết bên nào là attacker,
nên cách an toàn duy nhất là giết toàn bộ phiên và buộc user login lại. User mất 30 giây
đăng nhập lại < attacker chiếm tài khoản.

**Một user có thể có nhiều family song song** nếu họ login trên nhiều thiết bị:

```
alice trên điện thoại  → Family A
alice trên laptop      → Family B   ← bị compromise → chỉ Family B bị revoke
alice trên iPad        → Family C
```

→ Family cô lập tác động của vụ trộm vào đúng phiên bị xâm phạm; các thiết bị khác không
bị ảnh hưởng.

### File chính

- [`RefreshTokenService`](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) — xoay vòng + phát hiện tái sử dụng.
- [`RefreshToken`](src/main/java/com/demo/authpoc/jwt/RefreshToken.java) — record lưu `familyId`, `used`, `revoked`.
- [`JwtService`](src/main/java/com/demo/authpoc/jwt/JwtService.java) — phát hành/xác thực access token HS256.
- [`AuthController`](src/main/java/com/demo/authpoc/jwt/AuthController.java) — `/api/auth/{login,refresh,logout}` + `/api/me`.

### Những điểm POC này đơn giản hoá (đọc trước khi áp dụng vào production)

- Refresh token được giữ trong bộ nhớ và lưu ở dạng raw. Trong DB thật, hãy lưu **hash**.
- Khoá ký nằm trong `application.yml`. Thực tế phải inject qua env / KMS / Vault.
- Dùng chung một secret HS256 nghĩa là mọi service xác thực token đều cần secret đó. Khi việc
  xác thực được tách ra nhiều service, hãy ưu tiên **RS256/EdDSA + JWKS**.
- Không có introspection / danh sách thu hồi cho *access* token — chúng được coi là hợp lệ cho
  đến khi hết hạn. Giữ TTL của access token ngắn (~5 phút như ở đây).

---

## Demo 2 — Luồng OAuth 2.1 Authorization Code với PKCE

Một ứng dụng đóng ba vai trò: **authorization server**, **resource server** (`/api/me`),
và một **public client demo** dưới đường dẫn `/client/**`. PKCE (`S256`) là bắt buộc với client.

### Thao tác từng bước (trên trình duyệt)

1. Mở <http://localhost:8080> → nhấn **Start PKCE flow**.
2. Client sẽ:
    - sinh ngẫu nhiên `code_verifier`,
    - tính `code_challenge = base64url(SHA-256(code_verifier))`,
    - lưu `verifier` + `state` vào HTTP session của nó,
    - redirect tới `/oauth/authorize?...&code_challenge=...&code_challenge_method=S256&state=...`.
3. Bạn đăng nhập (alice/wonderland). Auth server lưu challenge cùng với một authorization code
   dùng một lần và redirect ngược về `/client/callback?code=...&state=...`.
4. Client kiểm tra `state`, POST tới `/oauth/token` kèm `code` + `code_verifier`. Auth server
   tính lại `SHA-256(code_verifier)`, so sánh (constant-time) với challenge đã lưu, và nếu khớp
   thì trả về access token.
5. Client gọi `/api/me` với `Authorization: Bearer …` và hiển thị kết quả.

### Thao tác từng bước (thủ công bằng curl)

```bash
# Sinh verifier + challenge (dùng Python cho ngắn gọn).
python3 -c "
import os, base64, hashlib
v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print('verifier ',v); print('challenge',c)
"
```

Sau đó mở trên trình duyệt:

```
http://localhost:8080/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/client/callback&scope=USER&state=xyz&code_challenge=<CHALLENGE>&code_challenge_method=S256
```

Đăng nhập. Trình duyệt sẽ được redirect kèm `?code=...`. Đổi code lấy token:

```bash
curl -s -X POST localhost:8080/oauth/token \
  -d grant_type=authorization_code \
  -d code=<CODE> \
  -d redirect_uri=http://localhost:8080/client/callback \
  -d client_id=demo-client \
  -d code_verifier=<VERIFIER> | jq
```

Thử đổi cùng code lần thứ hai → `400 invalid_grant: code already used`.
Thử với `code_verifier` sai → `400 invalid_grant: PKCE verification failed`.

### File chính

- [`PkceUtils`](src/main/java/com/demo/authpoc/oauth/PkceUtils.java) — tiện ích verifier/challenge và hàm `verify` constant-time.
- [`AuthorizationServerController`](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) — `/oauth/authorize` + `/oauth/token`.
- [`AuthorizationCodeStore`](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java) — code dùng một lần, thời hạn ngắn.
- [`ClientDemoController`](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java) — phần phía trình duyệt của handshake.

### Những điểm POC này đơn giản hoá

- Không có `openid` / id_token, không có refresh token ở phía OAuth, không có scope/consent UI
  ngoài thao tác "đăng nhập để cấp quyền".
- Authorization code lưu trong bộ nhớ; ở production nên đặt trong store TTL ngắn (Redis).
- Client demo và AS dùng chung Spring session cho tiện. Public client thật (SPA / mobile) phải
  tự lưu `verifier` và `state` trong storage riêng.
- Cố ý từ chối `code_challenge_method=plain` — chỉ chấp nhận `S256`.

---

## Các kỹ thuật bảo mật đáng chú ý

Danh sách rút gọn các kỹ thuật **đáng học** — những thứ dễ bỏ sót nhưng bảo vệ trước các lỗ
hổng có thật.

### Feature 1 — JWT + Refresh rotation

| Kỹ thuật | Tại sao quan trọng | Vị trí |
|----------|---------------------|--------|
| **Refresh token opaque** (không phải JWT) | Server toàn quyền kiểm soát state — revoke tức thì. JWT refresh không thể revoke trước khi hết hạn. | [RefreshToken.java](src/main/java/com/demo/authpoc/jwt/RefreshToken.java) |
| **Token family + reuse detection** | Một token đã rotate bị đánh cắp → revoke cả family → cả attacker và user đều bị đá ra → buộc login lại → giới hạn phạm vi thiệt hại. | [RefreshTokenService.java:72-78](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) |
| **`requireIssuer` khi verify JWT** | Từ chối token sinh bởi authority khác (dù dùng cùng secret) — chống cross-tenant. | [JwtService.java:49](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| **JWT có `jti`** | Mỗi token có ID riêng — future-proof cho revocation list / token introspection. | [JwtService.java:35](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| **Permissive auth filter** | Filter set context nếu token hợp lệ, **không reject** nếu sai — để `authorizeHttpRequests` quyết định. Tách trách nhiệm rõ ràng. | [JwtAuthenticationFilter.java:53-55](src/main/java/com/demo/authpoc/jwt/JwtAuthenticationFilter.java) |
| **`SecureRandom` + 256-bit + URL-safe base64** | CSPRNG + đủ entropy + an toàn dùng trong URL/cookie/header. | [RefreshTokenService.java:108-112](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) |
| **BCrypt cho password** | Adaptive hash + tự salt; chậm có chủ đích để chống brute-force. | [SecurityConfig.java:17-19](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |
| **`volatile` flag + `ConcurrentHashMap`** | Visibility giữa thread cho in-memory store. **Lưu ý:** không atomic check-then-act — production cần DB transaction hoặc `compareAndSet`. | [RefreshToken.java:19-20](src/main/java/com/demo/authpoc/jwt/RefreshToken.java) |

### Feature 2 — OAuth 2.1 + PKCE

| Kỹ thuật | Tại sao quan trọng | Vị trí |
|----------|---------------------|--------|
| **So sánh PKCE constant-time** (`MessageDigest.isEqual`) | `String.equals()` short-circuit ở byte sai đầu tiên → lộ thời gian → attacker brute-force từng byte. Constant-time chặn timing attack. | [PkceUtils.java:50-53](src/main/java/com/demo/authpoc/oauth/PkceUtils.java) |
| **Authorization code dùng 1 lần, atomic consume** | Mỗi code đổi được đúng 1 lần — lần 2 → `invalid_grant: code already used`. Replay defence kinh điển. | [AuthorizationCodeStore.java:41-52](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java) |
| **Từ chối `code_challenge_method=plain`** | `plain` để lộ verifier nếu authorize request bị intercept → mất hoàn toàn ý nghĩa PKCE. OAuth 2.1 bắt buộc S256. | [AuthorizationServerController.java:63-65](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| **State parameter (chống CSRF)** | Client lưu state random vào session, callback phải khớp. Ngăn attacker inject auth code của họ vào session victim. | [ClientDemoController.java:53,74-82](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java) |
| **`redirect_uri` whitelist exact-match** | Khớp **chính xác** với danh sách đã đăng ký (không prefix). Chặn open redirect → tránh code rò rỉ về domain attacker. Check ở **cả** `/authorize` lẫn `/token`. | [AuthorizationServerController.java:57-59,126-128](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| **`client_id` ràng buộc với code khi consume** | Code chỉ đổi được bởi đúng client đã yêu cầu — chống cross-client code injection. | [AuthorizationServerController.java:123-125](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| **Auth code TTL ngắn (60s)** | Cửa sổ để code bị intercept tận dụng được rất nhỏ. | [application.yml:18](src/main/resources/application.yml) |
| **Server lưu challenge** | Server lưu `code_challenge` khi cấp code và verify `verifier` ở `/token` — client không thể tự chế cả hai đầu. | [AuthorizationCode.java](src/main/java/com/demo/authpoc/oauth/AuthorizationCode.java) |

### Áp dụng chung (cả 2 feature)

| Kỹ thuật | Tại sao quan trọng | Vị trí |
|----------|---------------------|--------|
| **Validation ở boundary** (`@Valid` + `@NotBlank`) | Spring tự reject request sai format bằng 400 trước khi tới logic. | [LoginRequest.java](src/main/java/com/demo/authpoc/jwt/dto/LoginRequest.java) |
| **Centralized exception mapping** | Custom exception → OAuth error code chuẩn. Không leak stack trace ra client. | [ApiExceptionHandler.java](src/main/java/com/demo/authpoc/web/ApiExceptionHandler.java) |
| **Java `record` cho DTO / value object** | Bất biến (immutable) — an toàn truyền qua thread. | [`User`](src/main/java/com/demo/authpoc/user/User.java), [`AuthorizationCode`](src/main/java/com/demo/authpoc/oauth/AuthorizationCode.java)... |
| **CSRF disabled có chủ đích** | API stateless dùng Bearer token, không có cookie session → CSRF không áp dụng. OAuth flow dùng `state` riêng. | [SecurityConfig.java:25](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |

### Top 5 kỹ thuật "thầm lặng" đáng nhớ

1. **`MessageDigest.isEqual`** — so sánh constant-time, chống timing attack ở PKCE verify.
2. **Code dùng 1 lần + atomic consume + reuse detection** — replay defence cốt lõi của protocol.
3. **`requireIssuer` khi verify JWT** — bảo vệ cross-tenant, thường bị quên.
4. **`redirect_uri` exact-match ở cả 2 endpoint** — chặn chuỗi open-redirect → code-leak.
5. **OAuth `state` parameter** — CSRF defence dành riêng cho OAuth flow.

Đây là những thứ spec **gợi ý nhưng không bắt buộc rõ ràng** — dễ bỏ qua, nhưng thiếu là có lỗ hổng.
