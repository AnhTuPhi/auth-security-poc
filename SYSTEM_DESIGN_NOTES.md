# System Design Notes — Identity Platform ở doanh nghiệp lớn

> Ghi chú tham khảo về cách bigtech tách user/account management khỏi auth service,
> kèm link tới papers, blog posts, và best practices. Đọc dần, không cần đọc 1 lần.

---

## Câu hỏi nền

> "Doanh nghiệp lớn có để user/account management chung service với authN/authZ không?
> Mô hình của họ ra sao?"

**Trả lời ngắn:** **Không.** Bigtech gần như luôn **tách** ra thành nhiều service nhỏ
chuyên trách, tổng thể gọi là **Identity Platform**. Lý do: scale khác nhau, security
boundary khác nhau, ownership khác nhau, compliance khác nhau.

---

## 1. Mô hình kiến trúc phổ biến

```
                    ┌──────────────────────────────────────────┐
                    │           Identity Platform              │
                    │                                          │
   ┌─────────┐      │  ┌──────────────┐    ┌───────────────┐  │      ┌──────────────┐
   │ Client  │◄────►│  │ Auth Service │    │ Authorization │  │      │   Business   │
   │ (Web/   │      │  │   (AuthN)    │    │   Service     │◄─┼─────►│   Services   │
   │ Mobile) │      │  │ login, MFA,  │    │ (AuthZ, RBAC, │  │      │ (Order, Pay, │
   └─────────┘      │  │ token issue  │    │   policies)   │  │      │   Search...) │
                    │  └──────┬───────┘    └───────┬───────┘  │      └──────────────┘
                    │         │                    │           │
                    │         ▼                    ▼           │
                    │  ┌──────────────┐    ┌───────────────┐  │
                    │  │ User Profile │    │   Directory   │  │
                    │  │   Service    │    │   / Roles     │  │
                    │  │ (CRUD user,  │    │   / Groups    │  │
                    │  │ email, pwd,  │    │               │  │
                    │  │ preferences) │    │               │  │
                    │  └──────────────┘    └───────────────┘  │
                    │                                          │
                    │  ┌──────────────┐    ┌───────────────┐  │
                    │  │   Session    │    │   Audit /     │  │
                    │  │   Service    │    │   Risk Engine │  │
                    │  └──────────────┘    └───────────────┘  │
                    └──────────────────────────────────────────┘
```

### Vai trò từng service

| Service | Chức năng | Off-the-shelf option |
|---------|-----------|-----------------------|
| **Auth Service (IdP)** | Login, MFA, OAuth/OIDC, phát token | [Keycloak](https://www.keycloak.org/), [Ory Hydra](https://www.ory.sh/hydra/), Auth0, Okta, AWS Cognito |
| **User Profile Service** | CRUD user data, email, password hash, settings | Build riêng (Spring Boot + Postgres) |
| **Authorization Service** | RBAC/ABAC, policies, permission check | [OPA](https://www.openpolicyagent.org/), [SpiceDB](https://authzed.com/), [OpenFGA](https://openfga.dev/), [Permify](https://permify.co/) |
| **Directory Service** | Org tree, groups, roles | LDAP, AD, Okta Directory |
| **Session Service** | Quản lý session, refresh token state, blacklist | Redis-backed custom |
| **Risk / Fraud Engine** | Adaptive auth, anomaly detection, bot detection | Custom ML hoặc Castle.io, Sift |
| **Audit Service** | Log mọi auth event | Kafka → SIEM (Splunk, ELK, Datadog) |

---

## 2. Tại sao tách?

| Lý do | Giải thích |
|-------|-----------|
| **Scale khác nhau** | Auth = burst (peak khi user vào ngày). Profile = read-heavy, steady. Scale độc lập. |
| **Security boundary** | Auth service là crown jewel — code nhỏ, audit chặt, ít người commit. Profile có nhiều dev đụng vào. |
| **Ownership / Conway's Law** | Team Identity, team Account, team AuthZ thường là 3 team khác nhau. |
| **Compliance** | PII (profile) và credentials (auth) có yêu cầu pháp lý khác nhau (GDPR, SOC 2, HIPAA, PCI-DSS). Tách để scope audit nhỏ lại. |
| **Cache strategy** | Token cần invalidate ngay; profile data cache thoải mái vài phút. |
| **Failure isolation** | Profile service xuống không được làm sập login. |
| **Reuse** | Một IdP phục vụ nhiều product (Gmail + YouTube + Drive dùng chung Google Account). |

---

## 3. Kinh nghiệm bigtech đã share

### Google

- **[BeyondCorp](https://cloud.google.com/beyondcorp)** (2014–2017 paper series)
  Zero Trust pioneer. Google bỏ VPN, mọi request đều authenticated + authorized ở edge.
  Paper gốc: [research.google → BeyondCorp](https://research.google/pubs/?text=beyondcorp).

- **[Zanzibar paper](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)** (USENIX ATC '19)
  Authorization của Google Drive/YouTube/Cloud. Đẻ ra cả ngành authorization-as-a-service:
  SpiceDB, OpenFGA, Permify, Warrant.

- **Google Identity Platform** — tách OAuth/OIDC, account management, MFA, recovery riêng.

### Netflix

- **"Edge Authentication and Token-Agnostic Identity Propagation"** trên
  [Netflix Tech Blog](https://netflixtechblog.com/) (2018).
  Pattern **token exchange**: external OAuth token ở edge → đổi thành internal "Passport"
  token để propagate qua microservices.

- **BLESS** (Bastion's Lambda Ephemeral SSH Service) — short-lived SSH certs cho engineers,
  open source: <https://github.com/Netflix/bless>.

- Nhiều bài về token propagation, session management, MFA UX.

### Uber

- **USL (Uber's Identity)** — tách identity, session, authorization, user profile.
- Blog: <https://www.uber.com/blog/engineering/> (tìm "authentication", "identity").

### Slack

- Engineering blog: <https://slack.engineering/>
- Tách rõ: workspace identity vs user identity vs enterprise identity (Enterprise Grid).
- Nhiều bài về SAML, OIDC, SSO integration ở scale.

### Airbnb

- Engineering blog: <https://medium.com/airbnb-engineering>
- Identity service riêng cho user-facing, riêng cho service-to-service.

### Meta / Facebook

- [Engineering Blog](https://engineering.fb.com/)
- **Delegated Account Recovery** — public protocol, tách recovery khỏi auth.

### Amazon / AWS

- **IAM, Cognito, STS** là 3 service khác nhau dù nhìn từ ngoài có vẻ giống.
- Cognito = User Pools (account mgmt) + Identity Pools (federation) — chính Amazon cũng tách 2 thứ này.

### LinkedIn

- [Engineering Blog](https://engineering.linkedin.com/)
- Nhiều bài về OAuth 2.0 ở quy mô lớn, tách IdP khỏi profile service.

### Pinterest

- [Engineering Blog](https://medium.com/pinterest-engineering)
- Dùng Zanzibar-style authorization (SpiceDB).

### Cloudflare

- **[Cloudflare Access](https://blog.cloudflare.com/tag/cloudflare-access/)** — zero-trust auth proxy, nhiều bài chi tiết về thiết kế.

### Stripe

- **[Stripe Engineering](https://stripe.com/blog/engineering)** — nhiều bài về API key, OAuth Connect, account separation.

### GitHub

- **[GitHub Engineering Blog](https://github.blog/category/engineering/)** — fine-grained PAT, GitHub Apps tách hẳn khỏi user auth.

---

## 4. Reference Architectures đáng đọc

### 4.1 Google Zanzibar (2019)

[Paper](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) |
[Tóm tắt USENIX](https://www.usenix.org/conference/atc19/presentation/pang)

Hệ thống authorization global, tách hoàn toàn khỏi authn và user store. Permission lưu
dạng **relation tuples**: `doc:readme#viewer@user:alice`. Open-source implementations:

- [SpiceDB](https://authzed.com/spicedb) — by Authzed
- [OpenFGA](https://openfga.dev/) — by Auth0 / Okta
- [Permify](https://github.com/Permify/permify)
- [Warrant](https://github.com/warrant-dev/warrant)
- [Ory Keto](https://www.ory.sh/keto/)

### 4.2 BeyondCorp (Google)

[Paper series](https://research.google/pubs/?text=beyondcorp) |
[Product page](https://cloud.google.com/beyondcorp)

Zero Trust pioneer. Mọi request authenticated + authorized ở edge, không có "trusted
network". Các paper:
- BeyondCorp: A New Approach to Enterprise Security (2014)
- BeyondCorp: Design to Deployment (2016)
- BeyondCorp: The Access Proxy (2016)

### 4.3 NIST 800-63 Digital Identity Guidelines

[NIST SP 800-63](https://pages.nist.gov/800-63-3/)

Tách 3 phần rõ ràng:
- **800-63A** — Enrollment & Identity Proofing
- **800-63B** — Authentication & Lifecycle Management
- **800-63C** — Federation & Assertions

Chính phủ Mỹ chuẩn hoá việc tách identity/auth/federation.

### 4.4 OAuth 2.1 + OpenID Connect

[OAuth 2.1 draft](https://oauth.net/2.1/) |
[OpenID Connect](https://openid.net/connect/)

Bản thân spec đã tách:
- **Authorization Server** — issue token
- **Resource Server** — chứa data
- **UserInfo endpoint** — riêng cho profile

### 4.5 SCIM

[SCIM 2.0 (RFC 7644)](https://datatracker.ietf.org/doc/html/rfc7644)

Standard cho **user provisioning** — sync user giữa hệ thống (HR → IdP → SaaS apps).
Tách hẳn khỏi authentication protocol.

### 4.6 FIDO2 / WebAuthn

[WebAuthn spec](https://www.w3.org/TR/webauthn-2/) |
[FIDO Alliance](https://fidoalliance.org/)

Passwordless / passkeys. Tách credentials (sống ở hardware authenticator) khỏi profile.

---

## 5. Pattern cụ thể bigtech hay dùng

### Pattern 1 — Token Exchange + Internal Propagation

```
User → External OAuth token (public, short TTL, OIDC-compliant)
            ↓
       Edge Gateway
            ↓
  Token Exchange → Internal token (richer claims, propagation chain, trust level)
            ↓
   Service A → Service B → Service C (cùng dùng internal token, mTLS)
```

- **Netflix**: Passport
- **Google**: Loas (internal RPC auth)
- **Standard**: [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)

### Pattern 2 — Per-Request Authorization Check (Zanzibar-style)

Tách authz hoàn toàn ra global service. Business service hỏi: "user X có quyền Y trên
resource Z không?" → yes/no. Lưu permission dạng relation tuples để check sub-second
ở scale tỷ entries.

### Pattern 3 — Identity Federation / Brokered Auth

Auth service không lưu user — chỉ broker giữa các IdP (Google, Apple, enterprise SSO,
internal directory). User store là "source of truth" riêng, link qua external ID.

Ví dụ: Auth0, Firebase Auth, Supabase Auth.

### Pattern 4 — Short-Lived Everything

| Token type | TTL điển hình | Ghi chú |
|-----------|---------------|---------|
| Access token (user) | 5–15 phút | Refresh nhiều lần |
| Refresh token (user) | 7–30 ngày | Rotate + reuse detection |
| Service-to-service token | giây | mTLS underneath |
| SSH cert (engineer) | 1–8 giờ | Netflix BLESS |
| Database credential | phút | HashiCorp Vault dynamic secrets |

Triết lý: thà refresh thường xuyên còn hơn có long-lived token bị lộ.

### Pattern 5 — mTLS for Service-to-Service

Service không tin token đơn thuần — phải có mTLS (mutual TLS). Token chỉ chứa identity,
mTLS chứng minh "ai là người gửi". Dùng SPIFFE/SPIRE để cấp certs:
- [SPIFFE](https://spiffe.io/)
- [SPIRE](https://github.com/spiffe/spire)

### Pattern 6 — Step-Up Authentication

User đã login → khi làm hành động nhạy cảm (đổi password, transfer tiền) → yêu cầu MFA
lại. Token có claim `acr` (Authentication Context Class Reference) để service biết mức
độ xác thực.

---

## 6. Anti-patterns cần tránh

| Anti-pattern | Vì sao tệ |
|--------------|----------|
| **Monolith auth** chứa cả password, profile, role, session, audit trong cùng DB | Blast radius lớn, không thể scale từng phần |
| **Tự code OAuth/OIDC từ đầu cho production** | Spec phức tạp, có nhiều CVE đã biết. Dùng Keycloak/Ory/Auth0 |
| **Long-lived JWT làm "session"** không có revocation | Lộ token = chết 1-2 tuần |
| **Lưu role trong JWT** mà không refresh khi role đổi | Stale authorization — user bị fire vẫn admin được 5 phút |
| **Password reset chỉ qua email** không có MFA | Email compromise = full takeover |
| **Refresh token không rotate** | Bị đánh cắp = vĩnh viễn |
| **Authorization rải khắp code** | `if (user.role == "admin")` ở mọi service — không audit được |
| **Centralized session với DB lookup mọi request** | Auth service trở thành bottleneck |

---

## 7. Stack tham khảo cho dự án thực tế

### Startup / mid-size

```
Auth: Keycloak / Auth0 / Supabase Auth (managed)
User store: Postgres (riêng bảng users)
AuthZ: Casbin / OPA cho policy đơn giản
Session: Redis cho refresh token state
```

### Enterprise / scale lớn

```
Auth: Keycloak self-hosted / Ory Hydra (OAuth 2.1 + OIDC)
User: Microservice riêng + Postgres
Profile: Microservice riêng + Cassandra/DynamoDB (read-heavy)
AuthZ: SpiceDB / OpenFGA (Zanzibar-style)
Session: Redis cluster
Directory: LDAP / Okta Directory
Service auth: SPIFFE/SPIRE + mTLS
Secrets: HashiCorp Vault
Audit: Kafka → Splunk/ELK
```

### Cho POC này nếu mở rộng

Repo `auth-security-poc` hiện gộp Authorization Server + Resource Server + Client demo
trong 1 process. Nếu mở rộng thực tế nên tách:

1. **auth-service** — chỉ giữ `/api/auth/*` + `/oauth/*` (JWT issue, refresh rotation, PKCE)
2. **user-service** — `/users/*` CRUD profile, email verify, password reset
3. **resource-services** — business APIs, chỉ verify JWT (không issue)
4. **authz-service** — policy check API, dùng OPA hoặc SpiceDB
5. **redis** — refresh token family store
6. **postgres** — user data với encryption at rest

---

## 8. Reading list — đề xuất đọc theo thứ tự

### Bắt đầu (1–2 ngày)

1. [OAuth 2.0 Simplified](https://www.oauth.com/) — Aaron Parecki, free online book
2. [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics/) — IETF draft
3. [The Copenhagen Book](https://thecopenhagenbook.com/) — practical auth guide bằng tiếng Anh

### Trung cấp (1 tuần)

4. [RFC 6819 — OAuth 2.0 Threat Model](https://datatracker.ietf.org/doc/html/rfc6819)
5. [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
6. [BeyondCorp papers](https://research.google/pubs/?text=beyondcorp) — Google
7. Netflix Tech Blog — search "authentication", "identity"

### Nâng cao (1 tháng)

8. [Zanzibar paper](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)
9. [SPIFFE/SPIRE docs](https://spiffe.io/docs/)
10. [NIST 800-63-3](https://pages.nist.gov/800-63-3/) — full series
11. [Identity & Data Security for Web Development](https://www.oreilly.com/library/view/identity-and-data/9781491937006/) — O'Reilly book

### Khi build thật

12. [Auth0 Architecture Center](https://auth0.com/docs/get-started/architecture-scenarios)
13. [Keycloak Architecture](https://www.keycloak.org/docs/latest/server_admin/index.html)
14. [Okta Developer Blog](https://developer.okta.com/blog/) — Randall Degges, Brian Demers
15. [Ory's blog](https://www.ory.sh/blog/) — open-source identity stack

### Specs cần biết

- [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750 — Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 7644 — SCIM Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
- [RFC 8628 — Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [RFC 8693 — Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 9126 — Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126)
- [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)

---

## 9. Cheat sheet — câu hỏi nhanh

| Tình huống | Nên làm gì |
|------------|-----------|
| App nội bộ, < 1000 user | Keycloak self-hosted, 1 DB |
| SaaS B2C, < 100K user | Auth0 / Supabase managed |
| SaaS B2B với SSO | Auth0 / Okta + SAML/OIDC federation |
| Enterprise > 1M user | Build IdP riêng, Keycloak/Ory làm base, tách full microservices |
| Engineer access nội bộ | BeyondCorp model — Cloudflare Access / Pomerium / Teleport |
| API key cho developer | Tách hẳn khỏi user auth, có rotation + scope |
| Service-to-service | mTLS + SPIFFE, không dùng JWT trần |
| IoT / device | Device Authorization Grant (RFC 8628) |

---

## 10. Quan điểm cá nhân (chốt lại)

1. **Đừng monolith auth.** Tách ít nhất 3 service: AuthN, AuthZ, User Profile.
2. **Đừng tự code OAuth từ scratch cho prod.** Dùng Keycloak hoặc managed (Auth0/Okta).
3. **Refresh token rotation + reuse detection** là bắt buộc — POC này demo đúng pattern.
4. **Zanzibar-style authz** là tương lai — học sớm, không phí.
5. **Short-lived everything** + auto-refresh là best practice 2025+.
6. **Audit log mọi auth event** ngay từ ngày 1 — chữa cháy về sau cực khó.
7. **mTLS service-to-service** — JWT trần không đủ ở scale.
8. **Passkeys / WebAuthn** — bắt đầu support sớm, password đang dần chết.

---

*Tài liệu này tham khảo các bài blog, paper, và spec công khai. Link đã verify tại thời điểm
viết — có thể đổi/chết theo thời gian. Khi không truy cập được, dùng Wayback Machine.*
