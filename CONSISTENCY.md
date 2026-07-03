# CONSISTENCY.md — Scaling this system across k8s pods / VMs

> The POC keeps refresh tokens and authorization codes in **process memory**
> (`ConcurrentHashMap` inside `RefreshTokenService` and `AuthorizationCodeStore`).
> That is correct for a single JVM and **silently unsafe the moment you run more than one
> replica** — whether that's `kubectl scale --replicas=3` or a second VM behind a load
> balancer. This document explains exactly what breaks, why, and how to fix it.

Related: [ISSUE.md](ISSUE.md) §Scaling (S.1–S.3) · [TECHNICAL.md](TECHNICAL.md) tech-debt tables.

---

## 1. Where the state actually lives today

| State | Type | Home | Lifetime |
|-------|------|------|----------|
| Refresh tokens (value, family, `used`, `revoked`) | `ConcurrentHashMap<String,RefreshToken>` | [RefreshTokenService.java:36](src/main/java/com/demo/authpoc/jwt/RefreshTokenService.java) | JVM heap |
| Authorization codes (`consumed`, challenge, TTL) | `ConcurrentHashMap<String,AuthorizationCode>` | [AuthorizationCodeStore.java:18](src/main/java/com/demo/authpoc/oauth/AuthorizationCodeStore.java) | JVM heap |
| PKCE `verifier` + `state` (demo client) | `HttpSession` | [ClientDemoController.java:52](src/main/java/com/demo/authpoc/oauth/ClientDemoController.java) | Server session |
| Access-token validity | **none** (stateless JWT) | verified from the signing key | until `exp` |

The access token is the *only* piece that scales for free — any replica can verify a JWT with
just the shared secret, no lookup. **Everything with server-side state is the problem.**

---

## 2. Why horizontal scaling breaks it

Put a load balancer in front of N replicas. Requests for one logical flow land on **different**
replicas, but the state lives on only one.

### 2.1 The refresh-rotation break (the dangerous one)

```
                 ┌── Pod A (heap: {R1: family=F, used=false}) ──┐
Client ──login──►│  issues R1                                    │
                 └───────────────────────────────────────────────┘
                 ┌── Pod B (heap: {}) ───────────────────────────┐
Client ─refresh(R1)─► LB routes to Pod B → R1 unknown → 401       │
                 └───────────────────────────────────────────────┘
```

Two distinct failure modes, both bad:

- **Availability break:** `rotate(R1)` on a pod that never saw `R1` returns
  `Unknown refresh token`. Refresh works only when you get lucky and hit the same pod → users
  randomly logged out. A rolling deploy wipes *all* heaps → **everyone** logged out (S.1).
- **Security break (worse, and silent):** reuse detection depends on seeing the *same* token
  presented twice. If the legit rotation happened on Pod A and a **stolen** copy is replayed on
  Pod B, Pod B has no record that the token was already `used`. Depending on routing, theft is
  **not detected** — the entire point of POC 1 is quietly lost, with no error to alert you (S.2).

### 2.2 The authorization-code break

The auth code is issued (`/oauth/authorize`) on one pod and redeemed (`/oauth/token`) on
another. If they differ, `consume(code)` throws `unknown code` and every login fails. And the
single-use guarantee only holds *within* a pod — the same code could in principle be consumed
once on Pod A and once on Pod B, defeating replay protection (S.2 again).

### 2.3 The session break (demo client)

`verifier`/`state` live in `HttpSession`. Without sticky sessions or shared session storage, the
`/client/callback` can land on a pod with no session → `state` mismatch → flow fails.

### 2.4 The atomicity break (even with a shared store)

`rotate()` is **check-then-act**: read the token, see `used == false`, then `markUsed()`. Under
concurrency two requests can both read `false` before either writes `true` → both rotate. A
`volatile` flag gives visibility, **not atomicity** (S.3). Moving to a shared store does not fix
this by itself — the operation must be made atomic.

---

## 3. The fix: externalize state, make mutations atomic

The single principle: **replicas must be stateless; all shared, mutable auth state moves to a
store every replica reads and writes, and every check-then-act becomes one atomic operation.**

```
          ┌── Pod A ──┐
   LB ────►│ stateless │──┐
          └───────────┘  │      ┌──────────────────────────────┐
          ┌── Pod B ──┐  ├────► │ Redis  (refresh tokens,       │
   LB ────►│ stateless │──┤      │         auth codes, sessions)│
          └───────────┘  │      └──────────────────────────────┘
          ┌── Pod C ──┐  │      ┌──────────────────────────────┐
   LB ────►│ stateless │──┘────► │ Postgres (durable refresh    │
          └───────────┘         │           token families)     │
                                └──────────────────────────────┘
```

### 3.1 Refresh tokens → Redis and/or Postgres, hashed, atomic rotation

Store a **hash** of the token (never the raw value), keyed for O(1) lookup, with the family and
flags. Make rotation atomic so a used token can be consumed exactly once.

- **Postgres option** — one statement does check-and-act:
  ```sql
  UPDATE refresh_token
     SET used = true
   WHERE token_hash = :h AND used = false AND revoked = false AND expires_at > now()
  RETURNING family_id, user_id;   -- 0 rows ⇒ reject; if row was already used ⇒ reuse!
  ```
  A `RETURNING` of zero rows on a token that *exists but is used* is your reuse tripwire →
  `UPDATE refresh_token SET revoked = true WHERE family_id = :f` (revoke the family). Wrap in a
  transaction so detection + family revocation commit together.

- **Redis option** — atomic via a Lua script (or `WATCH`/`MULTI`): read the token, branch on
  `used`, either mark-used + write successor or revoke the family, all in one server-side
  script so no two replicas interleave. TTL the keys to the refresh-token lifetime.

Either way, `RefreshTokenService` keeps the *exact same public API* (`issueNewFamily`, `rotate`,
`revoke`, `revokeFamily`) — only the backing map changes. That's the payoff of having the store
behind a service already.

### 3.2 Authorization codes → Redis with delete-on-read

Auth codes are short-lived (60s) and single-use — a perfect fit for Redis with a TTL. Make
`consume()` an **atomic delete-and-return**:

```
GETDEL code:<value>     # Redis 6.2+: returns the value AND removes it in one op
```

If `GETDEL` returns nothing, the code was already consumed or expired → `invalid_grant`. Atomic
by construction, so replay protection holds across every replica. Set the key with
`SET code:<v> <json> EX 60 NX`.

### 3.3 Client PKCE/session state → shared sessions or client-side

- **Spring Session + Redis** (`spring-session-data-redis`) makes `HttpSession` shared across
  replicas → the demo client's `verifier`/`state` survive a callback landing on any pod.
- Better still for a *real* public client: keep `verifier`/`state` in the **client's own**
  storage (SPA memory / mobile secure storage), so the AS holds no per-user session at all.

### 3.4 Access tokens → already fine, with one caveat

Stateless JWTs need nothing shared — every replica verifies with the key. Two scaling notes:

- **Key distribution:** with HS256 every replica needs the shared secret. When *other* services
  must verify tokens too, switch to **RS256/EdDSA + a JWKS endpoint** so verifiers fetch the
  public key and the private key never leaves the issuer.
- **Revocation at scale:** if you ever need to kill an access token before `exp`, publish its
  `jti` to a shared denylist (Redis, TTL = token lifetime) and check it in the filter. The `jti`
  claim is already minted for exactly this.

---

## 4. Consistency model — what guarantee do you actually need?

| State | Required guarantee | Why | Store choice |
|-------|--------------------|-----|--------------|
| Refresh token rotation | **Strong / linearizable** single-use | A race that lets a used token rotate = the security hole | Postgres row-lock, or Redis single-key atomic (Lua/`GETDEL`) |
| Reuse detection → family revoke | **Read-your-writes** on the family | Must see the `used` flag set by the prior rotation | Same store as the token; commit detection+revoke together |
| Authorization code | **Strong** single-use | Replay defence | Redis `GETDEL` / DB unique-consume |
| Access-token verify | **None** (stateless) | Self-verifying from the key | n/a |
| Access-token denylist (optional) | Eventual is acceptable | Short TTL bounds the staleness window | Redis |

Key point: single-key atomic operations (one refresh token, one auth code) are exactly the
sweet spot where **Redis gives you linearizability cheaply** — you do *not* need distributed
transactions. The moment your operation touches one logical key atomically, a single-primary
Redis or a single-row Postgres update is sufficient and fast.

---

## 5. Kubernetes / VM specifics

| Concern | Guidance |
|---------|----------|
| **Replica count** | Make the deployment stateless first (§3), *then* `replicas: N` and an HPA are safe. |
| **Rolling deploys** | With in-memory state a rollout logs everyone out. After externalizing, pods are cattle — drain/replace freely. |
| **Sticky sessions** | A crutch, not a fix. It reduces (not eliminates) cross-pod misses and dies on the pod that holds the state. Prefer shared state over affinity. |
| **Liveness/readiness** | Readiness must check Redis/Postgres reachability — a pod that can't reach the token store must not receive traffic. |
| **`SecureRandom`** | Ensure adequate entropy in minimal container images (haveged / `/dev/urandom`); token unpredictability depends on it. |
| **Redis HA** | Sentinel or Cluster. For single-use atomicity, keep each key on a single primary; avoid multi-primary active-active for the token keyspace (conflicting writes defeat single-use). |
| **Clock skew** | TTL/`exp` checks compare timestamps across pods — run NTP; keep TTLs comfortably larger than max skew. |
| **Secret management** | JWT signing key and Redis/DB creds via k8s Secrets → env / mounted Vault, never in `application.yml`. |
| **Graceful shutdown** | `SIGTERM` → stop accepting traffic, finish in-flight; because state is external, no draining of token data is needed. |

---

## 6. Migration checklist (in-memory → horizontally scalable)

1. [ ] Add Redis (codes, sessions, optional access-token denylist) and Postgres (durable
       refresh-token families).
2. [ ] Replace the `ConcurrentHashMap` in `RefreshTokenService` with a repository; store
       **token hashes**, not raw values.
3. [ ] Make `rotate()` a **single atomic** operation (SQL `UPDATE … WHERE used=false RETURNING`,
       or a Redis Lua script). Detect reuse from "row exists but already used."
4. [ ] Replace `AuthorizationCodeStore` with Redis `SET … EX 60 NX` + `GETDEL` on consume.
5. [ ] Add Spring Session + Redis (or move PKCE/state fully client-side).
6. [ ] Move the signing key to env/KMS/Vault; if other services verify tokens, migrate
       HS256 → **RS256/EdDSA + JWKS**.
7. [ ] Add readiness probes for the external stores.
8. [ ] Load-test with `replicas ≥ 3`: confirm refresh works on any pod **and** that a replayed
       old token still trips family revocation across pods.

Passing step 8 is the real definition of done: the security guarantee must hold **regardless of
which replica** serves each request.

---

## 7. One-line summary

> The JWT *access* token already scales; the **stateful** parts — refresh-token rotation,
> reuse detection, and single-use auth codes — do not. Externalize them to a shared store and
> make each mutation atomic, and the same code scales from one pod to N without weakening a
> single security guarantee.
