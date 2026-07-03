# ISSUE — Problems this POC exists to solve

> This repo is not a product. It is a **reference implementation** that pins down the
> *hard, easy-to-get-wrong* parts of two authentication flows so the patterns can be
> lifted into real services with confidence. This file states the problems precisely —
> the "why we bothered" — before any code or design is discussed.

---

## Context

`auth-security-poc` is a single Spring Boot 3 / Java 21 app that plays several roles at once
(authorization server, resource server, and a demo public client). It demonstrates two
independent authentication-security patterns:

- **POC 1 — JWT access tokens + refresh-token rotation with reuse detection.**
- **POC 2 — OAuth 2.1 Authorization Code flow with mandatory PKCE (S256).**

Everything is deliberately in-memory so the app boots clean every run. That simplicity is a
feature for *learning* and a liability for *production* — the gap between the two is exactly
what the companion docs ([TECHNICAL.md](TECHNICAL.md), [CONSISTENCY.md](CONSISTENCY.md))
exist to make explicit.

---

## The core issue

**Authentication code is the one place in a system where a subtle mistake becomes a total
compromise.** A rounding bug in a report is an annoyance. A timing side-channel in a token
comparison, a refresh token that never rotates, or a `redirect_uri` matched by prefix instead
of exact string is an account-takeover primitive. The failure modes are:

1. **Silent** — the happy path works perfectly, so tests pass and demos look great. The hole
   only shows up when an attacker probes it.
2. **Well-documented for attackers, under-documented for builders** — the specs (RFC 6749,
   7636, OAuth 2.1 BCP) hint at the defences but rarely spell out "if you skip this exact
   line, here is the exploit."
3. **Tempting to hand-roll** — every framework makes it *look* easy to issue a JWT, so people
   do, and they skip rotation, revocation, issuer checks, and constant-time comparison.

The issue this POC addresses: **make the non-obvious defences concrete, named, tested, and
copy-pasteable, and be honest about what the in-memory shortcuts break when you scale.**

---

## Problem breakdown

### POC 1 — JWT refresh rotation

| # | Sub-problem | What goes wrong if ignored |
|---|-------------|----------------------------|
| 1.1 | Access tokens can't be revoked before expiry | Long-lived JWT + a leak = the attacker is in for the full TTL. |
| 1.2 | Refresh tokens are long-lived and high-value | A stolen refresh token is a permanent session unless it rotates. |
| 1.3 | Detecting that a refresh token was stolen | Without reuse detection, attacker and victim coexist silently for weeks. |
| 1.4 | Limiting blast radius once theft is detected | Revoking one token isn't enough if the attacker already rotated it. |
| 1.5 | Cross-tenant / cross-issuer token confusion | A token minted by another authority sharing the secret is accepted. |
| 1.6 | Tokens must be safe to transport (URL, header, cookie) | Weak randomness or non-URL-safe encoding leaks or breaks. |

### POC 2 — OAuth 2.1 + PKCE

| # | Sub-problem | What goes wrong if ignored |
|---|-------------|----------------------------|
| 2.1 | Authorization code interception (public clients: SPA / mobile) | Intercepted code → attacker exchanges it for a token. PKCE closes this. |
| 2.2 | PKCE verifier comparison leaking via timing | `String.equals` short-circuits → byte-by-byte brute force of the challenge. |
| 2.3 | Authorization code replay | A code exchanged twice = two valid sessions. Must be single-use, atomically. |
| 2.4 | `plain` PKCE method defeating the point | `plain` puts the verifier in the URL — no better than no PKCE. |
| 2.5 | Open redirect → code leakage | Loose `redirect_uri` matching sends the code to an attacker domain. |
| 2.6 | CSRF / code injection into a victim's session | Without `state`, an attacker injects their own code into your session. |
| 2.7 | Cross-client code injection | A code issued for client A exchanged by client B. |

### Cross-cutting

| # | Sub-problem | What goes wrong if ignored |
|---|-------------|----------------------------|
| X.1 | Malformed input reaching business logic | Null/blank credentials, injection, NPEs surfaced as 500s. |
| X.2 | Internal errors leaking to clients | Stack traces disclose structure; non-standard error shapes break clients. |
| X.3 | Secrets committed to config | Signing key in `application.yml` is a demo-only shortcut. |

### Scaling (the honest part)

| # | Sub-problem | What goes wrong if ignored |
|---|-------------|----------------------------|
| S.1 | In-memory token/code stores don't survive a restart | Every deploy logs everyone out; every crash loses reuse-detection state. |
| S.2 | In-memory stores aren't shared across pods/VMs | Refresh on pod B fails because the token lives only in pod A. **Reuse detection breaks — the security guarantee is silently lost.** |
| S.3 | `volatile` + `ConcurrentHashMap` is not atomic check-then-act | Concurrent refreshes can both succeed under a race. |

Sub-problems S.1–S.3 are the subject of [CONSISTENCY.md](CONSISTENCY.md).

---

## Non-goals

- Not a drop-in auth server. For production, prefer Keycloak / Ory Hydra / a managed IdP —
  see [SYSTEM_DESIGN_NOTES.md](SYSTEM_DESIGN_NOTES.md).
- No OIDC `id_token`, no consent UI, no MFA, no password reset, no user CRUD.
- No persistence, no clustering — those gaps are documented, not solved, on purpose.

---

## Definition of done (for the POC as a teaching artifact)

1. Each named defence has a single, obvious home in the code.
2. Each defence has a failing-attack path a reader can trigger (reuse, replay, wrong verifier,
   bad `redirect_uri`, state mismatch).
3. Every simplification that would be unsafe in production is written down next to what it
   would take to make it safe.
4. The scaling story (why the in-memory design breaks horizontally, and the fix) is explicit.

See [TECHNICAL.md](TECHNICAL.md) for the solution shape and [CONSISTENCY.md](CONSISTENCY.md)
for scaling.
