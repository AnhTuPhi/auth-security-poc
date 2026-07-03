# TECHNICAL.md — Solution shape, tech by responsibility, and tech debt

> Companion to [ISSUE.md](ISSUE.md) (the problems) and [CONSISTENCY.md](CONSISTENCY.md)
> (scaling). This file explains, per POC: **the hard problem**, **what we're protecting**,
> **the shape of the solution**, **which technique owns which responsibility**, **how each
> sub-problem is solved (with the exact code home)**, and **the tech debt to acknowledge.**

Read alongside the source. Every claim below points at a file.

---

## 0. System at a glance

One Spring Boot process wears several hats:

```
                       ┌───────────────────────────── auth-security-poc (1 JVM) ─────────────────────────────┐
  Browser / curl  ───► │  Authorization Server   Resource Server        Demo Public Client                    │
                       │  /oauth/authorize        /api/me                /client/login                         │
                       │  /oauth/token            /api/auth/*            /client/callback                       │
                       │        │                     │                        │                               │
                       │        ▼                     ▼                        ▼                               │
                       │  AuthorizationCodeStore  JwtAuthenticationFilter   RestClient (server-side call)      │
                       │  RefreshTokenService     JwtService                                                   │
                       │  ClientRegistry          UserService (BCrypt)                                         │
                       └────────────────────────────────────────────────────────────────────────────────────┘
```

Foundational choices that cut across both POCs:

| Choice | Responsibility | Where |
|--------|----------------|-------|
| Spring Security filter chain, **stateless for the API** | Authn plumbing, URL authorization | [SecurityConfig.java](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |
| **BCrypt** password hashing | Credential-at-rest protection | [SecurityConfig.java:17](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |
| **Java records** for DTOs / value objects | Immutability → thread-safety by construction | `User`, `AuthorizationCode`, `TokenResponse` |
| **Bean-validated DTOs** (`@Valid`, `@NotBlank`) | Reject malformed input at the boundary | [LoginRequest.java](src/main/java/com/demo/authpoc/jwt/dto/LoginRequest.java) |
| **Centralized exception → standard error mapping** | No stack-trace leakage; OAuth-style errors | [ApiExceptionHandler.java](src/main/java/com/demo/authpoc/web/ApiExceptionHandler.java) |

---

## POC 1 — JWT access tokens + refresh-token rotation

### The hard problem

JWTs are **stateless by design** — that is their whole value (any service can verify one with
just the key, no DB lookup) and their whole curse (**you cannot take one back**). So you're
caught between two bad options:

- **Long-lived JWT** → convenient, but a single leak grants the attacker a long session you
  can't revoke.
- **Short-lived JWT** → safe, but forces the user to log in constantly.

The refresh token resolves the tension — but a long-lived refresh token is now the crown jewel,
and **if it leaks you have re-created the original problem, worse.** The genuinely hard part is
therefore not "issue a JWT" — it's: *how do you detect that a long-lived refresh credential has
been stolen, and contain the damage, without a human in the loop?*

### What we're protecting

- **The user's session continuity** — they shouldn't have to re-auth every 5 minutes.
- **The refresh token** — the one credential that, if stolen, is a durable session.
- **The ability to react to theft** — turn a silent, weeks-long compromise into a
  forced re-login that kicks *both* parties out.

### Solution shape

Split the token into two tiers with opposite trade-offs, and make the long-lived tier
**stateful, single-use, and self-policing**:

```
login ──► access JWT   (HS256, 5 min, stateless, NOT revocable → kept short)
     └──► refresh token (opaque, 7 days, server-stored, single-use, ROTATES)

/refresh(R_old):
   R_old unknown / revoked / expired  ─► reject
   R_old already "used"               ─► THEFT: revoke whole family, reject
   otherwise                          ─► mark R_old used, mint R_new (same family)
```

The insight is the **token family + reuse detection**. Legitimate clients always present the
*newest* token; a thief who copied an earlier one will eventually present a token that's already
been `used`. That reuse is the tripwire — and because both the thief's copy and the victim's
live chain share a `familyId`, revoking the family ejects everyone and forces a clean re-login.

### Key tech by responsibility

| Responsibility | Technique | Where |
|----------------|-----------|-------|
| Mint / verify access token | JJWT `Jwts.builder`/`parser`, HS256 | [JwtService.java](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| Bind token to an authority | `.requireIssuer(issuer)` on verify | [JwtService.java:49](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| Future-proof revocation | `jti` (`UUID`) claim per token | [JwtService.java:35](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| Keep long-lived state revocable | **Opaque** token (not a JWT), server-stored | [RefreshToken.java](src/main/java/com/demo/authpoc/jwt/RefreshToken.java) |
| Single-use + rotation | `markUsed()` + `mint()` in one `rotate()` | [RefreshTokenService.java:55-82](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) |
| Theft detection & containment | reuse → `revokeFamily(familyId)` | [RefreshTokenService.java:72-78](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) |
| Unguessable token value | `SecureRandom` 256-bit → URL-safe base64 | [RefreshTokenService.java:108-112](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) |
| Populate security context per request | permissive `OncePerRequestFilter` | [JwtAuthenticationFilter.java](src/main/java/com/demo/authpoc/jwt/JwtAuthenticationFilter.java) |
| Route entry / exit | `/api/auth/{login,refresh,logout}`, `/api/me` | [AuthController.java](src/main/java/com/demo/authpoc/jwt/AuthController.java) |

### How each sub-problem is solved

- **1.1 Access token not revocable →** don't fight it; keep the TTL to **5 min**
  ([application.yml:15](src/main/resources/application.yml)) and carry a `jti` so a
  revocation/introspection list *can* be added later without changing the token shape.
- **1.2 Refresh token is high-value →** it's opaque and server-side, so the server has full
  control and can invalidate instantly — impossible with a self-contained JWT refresh token.
- **1.3 Detecting theft →** every token is single-use. Presenting a `used` token is treated as
  proof of copying ([RefreshTokenService.java:72](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java)).
- **1.4 Containing blast radius →** reuse revokes the **entire family**, not just the presented
  token, so a thief who already rotated once is still ejected
  ([RefreshTokenService.java:92-96](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java)).
- **1.5 Cross-issuer confusion →** `requireIssuer` rejects a validly-signed token minted by a
  different authority sharing the secret.
- **1.6 Safe transport →** `SecureRandom` (CSPRNG) + 256 bits of entropy + URL-safe,
  unpadded base64.

### The permissive filter (a deliberate design point)

The JWT filter **authenticates but never rejects** — an invalid token simply leaves the context
empty and `authorizeHttpRequests` decides the outcome
([JwtAuthenticationFilter.java:53-55](src/main/java/com/demo/authpoc/jwt/JwtAuthenticationFilter.java)).
This keeps "who are you?" (the filter) cleanly separated from "are you allowed here?" (the
authorization rules), and lets public endpoints stay public even with a garbage token attached.

### Tech debt to acknowledge (POC 1)

| Debt | Impact | Production fix |
|------|--------|----------------|
| Refresh tokens stored **in memory as raw values** | Lost on restart; a store dump leaks live tokens | Persist in Postgres/Redis, store a **hash** only |
| Reuse-detection state is **per-process** | With >1 pod, reuse detection silently fails | Shared store — see [CONSISTENCY.md](CONSISTENCY.md) |
| `rotate()` is **check-then-act, not atomic** (`volatile` flag) | Two concurrent refreshes could both win | DB transaction / `UPDATE … WHERE used=false` / `compareAndSet` |
| **HS256 single shared secret** | Every verifier needs the secret; no key isolation | **RS256/EdDSA + JWKS** when validation is split across services |
| Signing secret in `application.yml` | Secret in source control | Inject via env / KMS / Vault |
| No revocation/introspection list for **access** tokens | A leaked access token is valid until expiry | Short TTL now; add a `jti` denylist if needed |

---

## POC 2 — OAuth 2.1 Authorization Code flow + PKCE

### The hard problem

The Authorization Code flow was designed for **confidential** clients that can keep a secret.
**Public** clients — SPAs and mobile apps — can't: their "secret" ships to every user's device.
So the authorization **code**, in transit through the browser (redirects, the address bar,
logs, custom URL schemes on mobile), becomes interceptable. Anyone who grabs it can exchange it
for a token. The hard problem: **prove that the party redeeming the code is the same party that
started the flow — without a client secret.**

Layered on top are the classic redirect-based attacks: CSRF via the callback, open-redirect
code leakage, code replay, and cross-client code injection. Each has a specific, cheap defence
that is trivially forgotten.

### What we're protecting

- **The authorization code** in transit (the interception target).
- **The token exchange** against replay and against the wrong client redeeming a code.
- **The user's session** against an attacker injecting their own code (CSRF).
- **The redirect** against pointing at an attacker-controlled URL.

### Solution shape — PKCE binds start and finish

```
client: verifier = random;  challenge = base64url(SHA-256(verifier))     # verifier stays local
   │  /authorize?...&code_challenge=<challenge>&code_challenge_method=S256&state=<S>
   ▼
AS: login → issue single-use code, STORE the challenge against it → redirect ?code&state=<S>
   │  client checks state == S     (CSRF gate)
   │  /token  code + verifier      (verifier revealed only now, over a back-channel POST)
   ▼
AS: recompute SHA-256(verifier), constant-time compare to stored challenge → issue access token
```

Only the **hash** of the secret ever travels through the interceptable front-channel; the
secret itself (`verifier`) is revealed only in the back-channel token POST, and only *after* the
code is spent. An intercepted code is useless without the matching verifier.

### Key tech by responsibility

| Responsibility | Technique | Where |
|----------------|-----------|-------|
| Bind flow start↔finish | PKCE `S256`: challenge = base64url(SHA-256(verifier)) | [PkceUtils.java](src/main/java/com/demo/authpoc/oauth/PkceUtils.java) |
| Compare secrets safely | **constant-time** `MessageDigest.isEqual` | [PkceUtils.java:50-53](src/main/java/com/demo/authpoc/oauth/PkceUtils.java) |
| Reject weak PKCE | refuse `plain`, require `S256` | [PkceUtils.java:46](src/main/java/com/demo/authpoc/oauth/PkceUtils.java), [AuthorizationServerController.java:63](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| Single-use codes | atomic `consume()` → `code already used` on replay | [AuthorizationCodeStore.java:41-52](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java) |
| Short interception window | 60-second code TTL | [application.yml:18](src/main/resources/application.yml) |
| Redirect safety | **exact-match** whitelist, checked at authorize *and* token | [AuthorizationServerController.java:57,126](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| Bind code to its client | `client_id` match at consume | [AuthorizationServerController.java:123](src/main/java/com/demo/authpoc/oauth/AuthorizationServerController.java) |
| CSRF on the callback | `state` generated, stored, compared | [ClientDemoController.java:52,79](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java) |
| Client / code metadata | `ClientRegistry`, `AuthorizationCode` record | [ClientRegistry.java](src/main/java/com/demo/authpoc/oauth/ClientRegistry.java) |

### How each sub-problem is solved

- **2.1 Code interception →** PKCE. The intercepted code can't be redeemed without the
  `verifier`, which never crossed the front-channel.
- **2.2 Timing side-channel →** the verifier↔challenge comparison uses
  `MessageDigest.isEqual`, which does not short-circuit on first mismatch, defeating
  byte-by-byte brute forcing of the challenge.
- **2.3 Code replay →** `consume()` flips a `consumed` flag and throws
  `invalid_grant: code already used` on the second attempt.
- **2.4 `plain` defeats PKCE →** both the util and the authorize endpoint hard-reject anything
  but `S256`.
- **2.5 Open-redirect code leak →** `redirect_uri` must be an **exact** member of the client's
  registered list (not a prefix), enforced at **both** `/authorize` and `/token`.
- **2.6 CSRF / code injection →** the client generates a random `state`, stores it in its
  session, and rejects the callback unless it matches
  ([ClientDemoController.java:79](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java)).
- **2.7 Cross-client injection →** the code records the `client_id` that requested it; a
  mismatch at the token endpoint is `invalid_grant`.

### Why the AS stores the challenge (not the client)

The server persists `code_challenge` when it issues the code and verifies the `verifier`
against *that stored value* at `/token`
([AuthorizationCode.java](src/main/java/com/demo/authpoc/oauth/AuthorizationCode.java)). The
client can't present a challenge and a matching verifier of its own choosing — it's pinned to
what was registered against the code at authorize time.

### Tech debt to acknowledge (POC 2)

| Debt | Impact | Production fix |
|------|--------|----------------|
| Auth codes stored **in memory** | Lost on restart; not shared across pods | Short-TTL Redis; see [CONSISTENCY.md](CONSISTENCY.md) |
| Demo client shares the **AS's Spring session** | Real SPA/mobile keep `verifier`/`state` in their own storage | Separate the client process; session/PKCE state client-side |
| No `openid` / `id_token`, no refresh on OAuth side, no consent UI | Not a full IdP | Adopt Keycloak / Ory Hydra for real OIDC |
| Single hard-coded demo client, no client auth for confidential clients | Fine for a public-client demo only | Client registration + secret/mTLS for confidential clients |
| `consume()` atomicity relies on a single JVM | Concurrent redeem race across pods | Atomic delete-on-read in Redis / DB row lock |

---

## Cross-cutting concerns

| Concern | Technique | Where |
|---------|-----------|-------|
| **X.1 Malformed input** | `@Valid` + `@NotBlank` DTOs → 400 before business logic | [LoginRequest.java](src/main/java/com/demo/authpoc/jwt/dto/LoginRequest.java) |
| **X.2 Error leakage** | custom exceptions → OAuth-standard codes, no stack traces | [ApiExceptionHandler.java](src/main/java/com/demo/authpoc/web/ApiExceptionHandler.java), [OAuthException.java](src/main/java/com/demo/authpoc/oauth/OAuthException.java) |
| **X.3 CSRF disabled — on purpose** | stateless Bearer APIs carry no session cookie, so CSRF N/A; OAuth uses `state` instead | [SecurityConfig.java:25](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |
| Immutability | Java records everywhere for value objects | `User`, `AuthorizationCode`, DTOs |

---

## The five "silent" techniques worth memorizing

These are the ones the specs imply but don't shout — cheap to add, painful to omit:

1. **`MessageDigest.isEqual`** — constant-time compare kills the PKCE timing side-channel.
2. **Single-use code + refresh reuse detection** — replay/theft defence baked into the protocol.
3. **`requireIssuer` on JWT verify** — the cross-tenant guard everyone forgets.
4. **`redirect_uri` exact-match at *both* endpoints** — breaks the open-redirect → code-leak chain.
5. **OAuth `state`** — the CSRF defence specific to redirect-based flows.

---

## Where to go next

- **Scaling this design horizontally (k8s pods / VMs):** [CONSISTENCY.md](CONSISTENCY.md).
- **How real companies split auth into services:** [SYSTEM_DESIGN_NOTES.md](SYSTEM_DESIGN_NOTES.md).
- **Spring Security filter-chain internals:** [SPRING_SECURITY_INTERNALS.md](SPRING_SECURITY_INTERNALS.md).
- **Runnable, step-by-step attack/defence demos:** [WALKTHROUGH.md](WALKTHROUGH.md).
- **Visual explainer (open in a browser):** [docs/explainer.html](docs/explainer.html).
