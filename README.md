# auth-security-poc

A single Spring Boot 3 app (Java 21) demonstrating two authentication-security patterns:

1. **JWT refresh token rotation** with reuse detection (server-side opaque refresh tokens).
2. **OAuth 2.1 Authorization Code flow + PKCE** (S256), with an in-process demo public client.

Everything is in-memory so the POC starts clean every run. Demo users:

## Documentation map

Start here depending on what you need:

| Doc | What it answers |
|-----|-----------------|
| **[ISSUE.md](ISSUE.md)** | *Why this exists* — the precise problems and sub-problems each POC guards against. |
| **[TECHNICAL.md](TECHNICAL.md)** | *How it's solved* — per POC: the hard problem, what we protect, solution shape, key tech **by responsibility**, how each sub-problem maps to code, and the tech debt to acknowledge. |
| **[CONSISTENCY.md](CONSISTENCY.md)** | *Scaling* — exactly what breaks when you run >1 replica (k8s pods / VMs) and how to fix it with a shared store + atomic mutations. |
| **[docs/explainer.html](docs/explainer.html)** | *Visual explainer* — open in a browser for interactive flow diagrams and an animated token-lifecycle demo. |
| [WALKTHROUGH.md](WALKTHROUGH.md) | Runnable, step-by-step attack/defence demos. |
| [SYSTEM_DESIGN_NOTES.md](SYSTEM_DESIGN_NOTES.md) | How real companies split auth into services. |
| [SPRING_SECURITY_INTERNALS.md](SPRING_SECURITY_INTERNALS.md) | Spring Security filter-chain internals. |


| Username | Password    | Roles       |
|----------|-------------|-------------|
| alice    | wonderland  | USER        |
| bob      | builder     | USER, ADMIN |

---

## Prerequisites

- Java 21 (already installed).
- Maven 3.9+ — install with `brew install maven`.

## Run

```bash
cd /Users/pat/Documents/Code/Github/auth-security-poc
mvn spring-boot:run
```

Then open <http://localhost:8080>.

## Run the tests

```bash
mvn test
```

---

## Demo 1 — JWT refresh token rotation

Short-lived JWT access tokens (5 min) paired with long-lived opaque refresh tokens (7 days).
Each `/refresh` call rotates the refresh token: the presented one is marked **used** and a
fresh one is issued in the same **family**. Presenting a used token a second time is taken as
proof of theft — the whole family is revoked.

### Walk-through

```bash
# 1. Log in.
LOGIN=$(curl -s localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"wonderland"}')
echo "$LOGIN" | jq

ACCESS=$(echo "$LOGIN"  | jq -r .accessToken)
REFRESH=$(echo "$LOGIN" | jq -r .refreshToken)

# 2. Call a protected endpoint.
curl -s localhost:8080/api/me -H "Authorization: Bearer $ACCESS" | jq

# 3. Rotate.
ROT=$(curl -s localhost:8080/api/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}")
echo "$ROT" | jq
NEW_REFRESH=$(echo "$ROT" | jq -r .refreshToken)

# 4. Try to reuse the OLD refresh token → reuse detection kicks in,
#    and the whole family is revoked (so $NEW_REFRESH is also dead).
curl -s -i localhost:8080/api/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"
# 401 invalid_grant — "Refresh token reuse detected; family revoked"

curl -s -i localhost:8080/api/auth/refresh \
  -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$NEW_REFRESH\"}"
# 401 invalid_grant — "Refresh token revoked"
```

### Key files

- [`RefreshTokenService`](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) — rotation + reuse detection.
- [`JwtService`](src/main/java/com/demo/authpoc/jwt/JwtService.java) — HS256 access token mint/verify.
- [`AuthController`](src/main/java/com/demo/authpoc/jwt/AuthController.java) — `/api/auth/{login,refresh,logout}` + `/api/me`.

### What this POC simplifies (read before borrowing in prod)

- Refresh tokens are kept in-memory and stored as raw values. Store a **hash** in a real DB.
- The signing key is in `application.yml`. Inject via env / KMS / Vault in real life.
- A single HS256 secret means every service that validates tokens needs the secret. Prefer
  **RS256/EdDSA + JWKS** when validation is split across services.
- No token introspection / revocation list for *access* tokens — they're considered valid
  until expiry. Keep the access TTL short (~5 min here).

---

## Demo 2 — OAuth 2.1 authorization code flow with PKCE

A single app plays three roles: **authorization server**, **resource server** (`/api/me`),
and a **demo public client** under `/client/**`. PKCE (`S256`) is mandatory for the client.

### Walk-through (browser)

1. Open <http://localhost:8080> → click **Start PKCE flow**.
2. The client:
   - generates a random `code_verifier`,
   - computes `code_challenge = base64url(SHA-256(code_verifier))`,
   - stashes `verifier` + `state` in its HTTP session,
   - redirects to `/oauth/authorize?...&code_challenge=...&code_challenge_method=S256&state=...`.
3. You log in (alice/wonderland). The auth server stores the challenge against a fresh
   single-use authorization code and redirects back to `/client/callback?code=...&state=...`.
4. The client checks `state`, POSTs to `/oauth/token` with the `code` + `code_verifier`. The
   auth server recomputes `SHA-256(code_verifier)`, compares it (constant-time) to the stored
   challenge, and on match returns an access token.
5. The client calls `/api/me` with `Authorization: Bearer …` and renders the result.

### Walk-through (curl, manual)

```bash
# Generate a verifier + challenge (Python here for brevity).
python3 -c "
import os, base64, hashlib
v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print('verifier ',v); print('challenge',c)
"
```

Then open in a browser:

```
http://localhost:8080/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/client/callback&scope=USER&state=xyz&code_challenge=<CHALLENGE>&code_challenge_method=S256
```

Log in. The browser will be redirected with `?code=...`. Exchange it:

```bash
curl -s -X POST localhost:8080/oauth/token \
  -d grant_type=authorization_code \
  -d code=<CODE> \
  -d redirect_uri=http://localhost:8080/client/callback \
  -d client_id=demo-client \
  -d code_verifier=<VERIFIER> | jq
```

Try the same exchange a second time → `400 invalid_grant: code already used`.
Try with the wrong `code_verifier` → `400 invalid_grant: PKCE verification failed`.

### Key files

- [`PkceUtils`](src/main/java/com/demo/authpoc/oauth/PkceUtils.java) — verifier/challenge helpers and constant-time `verify`.
- [`AuthorizationServerController`](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) — `/oauth/authorize` + `/oauth/token`.
- [`AuthorizationCodeStore`](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java) — short-lived, single-use codes.
- [`ClientDemoController`](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java) — the browser side of the handshake.

### What this POC simplifies

- No `openid` / id_token, no refresh tokens on the OAuth side, no scopes/consent UI beyond
  "log in to authorize".
- Auth codes live in memory; in prod they belong in a short-TTL store (Redis).
- The demo client and the AS share the same Spring session for convenience. Real public
  clients (SPA / mobile) keep `verifier` and `state` in their own storage.
- We deliberately reject `code_challenge_method=plain` — only `S256` is acceptable.

---

## Notable security techniques

A condensed list of the techniques worth borrowing — the ones that are easy to miss but
guard against real vulnerabilities.

### Feature 1 — JWT + refresh rotation

| Technique | Why it matters | Where |
|-----------|---------------|-------|
| **Opaque refresh tokens** (not JWT) | Server keeps full control of state — can revoke instantly. JWT refresh can't be revoked before expiry. | [RefreshToken.java](src/main/java/com/demo/authpoc/jwt/RefreshToken.java) |
| **Token family + reuse detection** | One stolen rotated token → whole family revoked → both attacker and user kicked out → forced re-login limits blast radius. | [RefreshTokenService.java:72-78](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) |
| **`requireIssuer` on JWT verify** | Rejects tokens minted by a different authority sharing the same secret (cross-tenant defence). | [JwtService.java:49](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| **`jti` claim** | Unique token ID — future-proofs revocation lists / token introspection. | [JwtService.java:35](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| **Permissive auth filter** | Filter sets context if token is valid, *does not reject* if invalid — `authorizeHttpRequests` decides. Cleaner separation of concerns. | [JwtAuthenticationFilter.java:53-55](src/main/java/com/demo/authpoc/jwt/JwtAuthenticationFilter.java) |
| **`SecureRandom` + 256-bit + URL-safe base64** | CSPRNG + enough entropy + safe to put in URLs/cookies/headers. | [RefreshTokenService.java:108-112](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) |
| **BCrypt for passwords** | Adaptive hash + auto-salt; slow on purpose. | [SecurityConfig.java:17-19](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |
| **`volatile` flags + `ConcurrentHashMap`** | Cross-thread visibility for the in-memory store. *Note:* not atomic check-then-act — production needs DB transactions or `compareAndSet`. | [RefreshToken.java:19-20](src/main/java/com/demo/authpoc/jwt/RefreshToken.java) |

### Feature 2 — OAuth 2.1 + PKCE

| Technique | Why it matters | Where |
|-----------|---------------|-------|
| **Constant-time PKCE compare** (`MessageDigest.isEqual`) | `String.equals()` short-circuits on first byte mismatch → timing side-channel. Constant-time prevents brute-forcing the challenge byte-by-byte. | [PkceUtils.java:50-53](src/main/java/com/demo/authpoc/oauth/PkceUtils.java) |
| **Atomic single-use authorization code** | Each code can be exchanged exactly once — second attempt → `invalid_grant: code already used`. Classic replay defence. | [AuthorizationCodeStore.java:41-52](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java) |
| **Reject `code_challenge_method=plain`** | `plain` leaks the verifier if the authorize request is intercepted — defeats PKCE's purpose. OAuth 2.1 mandates S256. | [AuthorizationServerController.java:63-65](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| **`state` parameter (CSRF defence)** | Client stores random state in its session and checks it matches in callback. Stops attacker from injecting their own auth code into the victim's session. | [ClientDemoController.java:53,74-82](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java) |
| **`redirect_uri` exact-match whitelist** | Exact match against the registered list (not prefix). Stops open-redirect → code leakage to attacker domains. Checked at *both* `/authorize` and `/token`. | [AuthorizationServerController.java:57-59,126-128](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| **`client_id` bound to the code at consume** | The code can only be exchanged by the client that requested it — prevents cross-client code injection. | [AuthorizationServerController.java:123-125](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| **Short auth-code TTL (60s)** | The window for an intercepted code to be useful is tiny. | [application.yml:18](src/main/resources/application.yml) |
| **Server stores the challenge** | Server saves `code_challenge` when issuing the code and verifies `verifier` against it at `/token` — client can't game both ends. | [AuthorizationCode.java](src/main/java/com/demo/authpoc/oauth/AuthorizationCode.java) |

### Cross-cutting

| Technique | Why it matters | Where |
|-----------|---------------|-------|
| **Validation at the boundary** (`@Valid` + `@NotBlank`) | Spring rejects malformed requests with 400 before any business logic runs. | [LoginRequest.java](src/main/java/com/demo/authpoc/jwt/dto/LoginRequest.java) |
| **Centralised exception mapping** | Custom exceptions → OAuth-standard error codes. No stack traces leaked to clients. | [ApiExceptionHandler.java](src/main/java/com/demo/authpoc/web/ApiExceptionHandler.java) |
| **Java records for DTOs / value objects** | Immutable by construction — safe to pass across threads. | [`User`](src/main/java/com/demo/authpoc/user/User.java), [`AuthorizationCode`](src/main/java/com/demo/authpoc/oauth/AuthorizationCode.java), etc. |
| **CSRF disabled — deliberately** | Stateless Bearer-token APIs don't carry session cookies, so CSRF doesn't apply. The OAuth flow uses its own `state` parameter instead. | [SecurityConfig.java:25](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |

### Top 5 "silent" techniques worth memorising

1. **`MessageDigest.isEqual`** — constant-time comparison defeats timing attacks (PKCE verify).
2. **Atomic single-use code + reuse detection** — replay defence baked into the protocol.
3. **`requireIssuer` on JWT verify** — cross-tenant guard often forgotten.
4. **`redirect_uri` exact-match (both endpoints)** — kills the open-redirect → code-leak chain.
5. **OAuth `state` parameter** — CSRF defence specific to the OAuth flow.

These are the ones the spec hints at but doesn't loudly demand — easy to skip, painful to miss.
