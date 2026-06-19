# Spring Security Internals — Under the hood

> Ghi chú chi tiết về (1) tech stack auth phổ biến ở enterprise và (2) cách Spring Security
> verify JWT token + xử lý `@PreAuthorize` từ A đến Z.

---

## Phần 1 — Tech stack cho Authentication / Authorization

### 1.1 Theo hệ sinh thái ngôn ngữ

| Stack | AuthN | AuthZ | Ghi chú |
|-------|-------|-------|---------|
| **Java/Kotlin** | Spring Security, **Spring Authorization Server**, Keycloak (cũng Java), Apereo CAS | Spring Method Security, OPA | Phổ biến nhất ở enterprise |
| **Node.js** | Passport.js, NextAuth, Lucia, Better Auth | CASL, OPA | Hệ sinh thái phong phú nhưng phân mảnh |
| **Go** | **Ory Kratos+Hydra+Oathkeeper**, Dex, Casdoor | Casbin, OPA, SpiceDB (cũng Go) | Cloud-native, dùng nhiều ở Kubernetes |
| **Python** | Django auth, FastAPI Security, Authlib | django-guardian, Oso, OPA | Lý tưởng cho startup nhanh |
| **Ruby** | Devise, Doorkeeper | CanCanCan, Pundit | Rails ecosystem |
| **.NET** | ASP.NET Identity, IdentityServer (Duende) | Built-in `[Authorize]` policies | Microsoft-heavy enterprises |
| **Rust** | OAuth2 crate, biscuit-auth | Biscuit tokens, Oso | Mới nổi |

### 1.2 Theo quy mô / tình huống

| Tình huống | Stack tiêu biểu |
|------------|-----------------|
| **Startup MVP** | Auth0 / Supabase Auth / Clerk / Firebase Auth — managed, $0–$200/mo |
| **Mid-size SaaS** | Keycloak self-hosted / AWS Cognito / Okta Workforce |
| **Enterprise B2B** | Okta / Microsoft Entra ID (Azure AD) / Ping Identity / ForgeRock |
| **Banking / Finance** | ForgeRock, IBM Security Verify, HSM-backed custom |
| **Big tech (FAANG)** | Tự build hoàn toàn — Google Loas, Netflix Passport, Meta TAOS |
| **Government** | ForgeRock, RSA SecurID, Yubico hardware |

### 1.3 Stack điển hình của một enterprise Java mid-size

```
┌─────────────────────────────────────────────────────────────┐
│ Edge: Nginx / Envoy / Kong (rate-limit, TLS terminate)     │
├─────────────────────────────────────────────────────────────┤
│ IdP: Keycloak (OAuth 2.1 + OIDC + SAML)                    │
│   ├── Realm config trong Git (GitOps)                      │
│   └── DB: Postgres                                          │
├─────────────────────────────────────────────────────────────┤
│ AuthZ: OPA sidecar mỗi service, hoặc SpiceDB cluster       │
├─────────────────────────────────────────────────────────────┤
│ Service-to-service: SPIFFE/SPIRE + mTLS (Istio service mesh)│
├─────────────────────────────────────────────────────────────┤
│ Business services: Spring Boot + Spring Security Resource  │
│   Server (verify JWT, check scope/role)                    │
├─────────────────────────────────────────────────────────────┤
│ Secrets: HashiCorp Vault                                   │
├─────────────────────────────────────────────────────────────┤
│ Audit: Kafka → Elasticsearch + Splunk                      │
└─────────────────────────────────────────────────────────────┘
```

### 1.4 Library cụ thể trong Spring world

| Mục đích | Library / Starter |
|----------|-------------------|
| Resource Server (verify JWT) | `spring-boot-starter-oauth2-resource-server` |
| Authorization Server | `spring-authorization-server` (mới, modern) |
| OAuth Client | `spring-boot-starter-oauth2-client` |
| Method security | `spring-security-core` + `@EnableMethodSecurity` |
| JWT codec | `nimbus-jose-jwt` (Spring default), hoặc `jjwt` (POC này) |
| Policy engine | `casbin-spring-boot-starter`, `opa-spring-boot` |
| AuthZ relation-based | `authzed-java` (SpiceDB client), `openfga-java-sdk` |

---

## Phần 2 — Under the hood: JWT verify + `@PreAuthorize`

### 2.1 Bức tranh tổng thể: 3 lớp bảo vệ

```
HTTP Request
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│ Servlet Container (Tomcat)                               │
│                                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │ DelegatingFilterProxy                            │   │
│   │   delegate → FilterChainProxy (Spring bean)      │   │
│   └────────────┬─────────────────────────────────────┘   │
│                ▼                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │ FilterChainProxy                                 │   │
│   │   chọn SecurityFilterChain matching request     │   │
│   └────────────┬─────────────────────────────────────┘   │
│                ▼                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │ SecurityFilterChain (~15 filter chạy lần lượt) │   │
│   │  ① SecurityContextHolderFilter                  │   │
│   │  ② LogoutFilter                                 │   │
│   │  ③ JwtAuthenticationFilter ★ ← custom của ta    │   │
│   │  ④ AnonymousAuthenticationFilter                │   │
│   │  ⑤ ExceptionTranslationFilter                   │   │
│   │  ⑥ AuthorizationFilter ★ ← check URL rule       │   │
│   └────────────┬─────────────────────────────────────┘   │
│                ▼                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │ DispatcherServlet → Controller method           │   │
│   │   AOP proxy với @PreAuthorize ★                 │   │
│   └─────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

3 nơi check security:
1. **Filter chain** — set up Authentication context
2. **AuthorizationFilter** — URL-level rules (`.authorizeHttpRequests`)
3. **Method security** — `@PreAuthorize` ở method (qua AOP proxy)

---

### 2.2 Chi tiết JWT verification

#### Bước 1 — `SecurityContextHolderFilter` (đầu chain)

Load `SecurityContext` từ session/repository vào `SecurityContextHolder`:

```java
public class SecurityContextHolder {
    private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();

    public static SecurityContext getContext() { ... }
    public static void setContext(SecurityContext context) { ... }
    public static void clearContext() { ... }
}
```

→ Mỗi request có 1 `SecurityContext` riêng (lưu `Authentication` hiện tại) trong `ThreadLocal`.

#### Bước 2 — `JwtAuthenticationFilter` (filter của POC này)

```java
@Override
protected void doFilterInternal(...) {
    String header = request.getHeader("Authorization");
    if (header != null && header.startsWith("Bearer ")) {
        String token = header.substring(7);
        try {
            Claims claims = jwtService.parseAndValidate(token);   // ← core verify
            // ... build Authentication ...
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (JwtException ex) {
            SecurityContextHolder.clearContext();
        }
    }
    chain.doFilter(request, response);
}
```

#### Bước 3 — `JwtService.parseAndValidate` (jjwt internals)

```java
public Claims parseAndValidate(String token) {
    Jws<Claims> jws = Jwts.parser()
            .verifyWith(signingKey)        // ← set HMAC key
            .requireIssuer(issuer)         // ← check iss
            .build()
            .parseSignedClaims(token);     // ← work here
    return jws.getPayload();
}
```

`parseSignedClaims(token)` làm 5 bước:

```
Token: "eyJhbGc...payload...signature"
         │
         ├─ Split bởi "."  → [header, payload, signature]
         │
         ├─ 1. Decode header (base64url)
         │     { "alg": "HS256", "typ": "JWT" }
         │     → kiểm `alg` khớp với key (chống alg confusion attack)
         │
         ├─ 2. Decode payload (base64url)
         │     { "iss": "...", "sub": "...", "exp": ..., "iat": ... }
         │
         ├─ 3. Verify signature:
         │     computed = HMAC-SHA256(signingKey, header + "." + payload)
         │     so sánh constant-time với signature từ token
         │     → mismatch → SignatureException
         │
         ├─ 4. Validate claims:
         │     exp < now → ExpiredJwtException
         │     iss != expected → IncorrectClaimException
         │     nbf > now → PrematureJwtException
         │
         └─ 5. Return Jws<Claims> object
```

#### Bước 4 — Build `Authentication`

```java
String username = claims.get("username", String.class);
String scope = claims.get("scope", String.class);
List<SimpleGrantedAuthority> authorities =
    Arrays.stream(scope.split(" "))
        .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
        .toList();

UsernamePasswordAuthenticationToken auth =
    new UsernamePasswordAuthenticationToken(username, null, authorities);
// principal = username
// credentials = null (token verified rồi, không cần giữ)
// authorities = [SCOPE_USER, SCOPE_ADMIN, ...]

SecurityContextHolder.getContext().setAuthentication(auth);
```

`UsernamePasswordAuthenticationToken` extends `AbstractAuthenticationToken` extends `Authentication`. Interface có các method:
- `getPrincipal()` — usually username
- `getAuthorities()` — danh sách quyền
- `isAuthenticated()` — boolean
- `getCredentials()` — password/token (null sau khi verify)

#### Bước 5 — `AuthorizationFilter` (filter cuối, Spring Security 6+)

Filter này thay thế `FilterSecurityInterceptor` từ Spring Security 6. Logic:

```java
@Override
protected void doFilterInternal(...) {
    AuthorizationDecision decision =
        authorizationManager.check(authentication, request);

    if (!decision.isGranted()) {
        throw new AccessDeniedException("Access Denied");
    }
    chain.doFilter(request, response);
}
```

`authorizationManager` được build từ `authorizeHttpRequests {...}` config:

```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/auth/**").permitAll()      // → PermitAllAuthorizationManager
    .requestMatchers("/admin/**").hasRole("ADMIN")    // → AuthorityAuthorizationManager
    .anyRequest().authenticated()                      // → AuthenticatedAuthorizationManager
)
```

Mỗi rule thành một `AuthorizationManager<RequestAuthorizationContext>`.
`RequestMatcherDelegatingAuthorizationManager` chọn matcher đầu tiên khớp và delegate.

#### Bước 6 — `ExceptionTranslationFilter` xử lý lỗi

Filter này wrap filter chain và catch:

```java
try {
    chain.doFilter(request, response);
} catch (AccessDeniedException e) {
    if (authentication is anonymous) {
        // user chưa login → 401
        authenticationEntryPoint.commence(...);   // → 401
    } else {
        // user đã login nhưng không đủ quyền → 403
        accessDeniedHandler.handle(...);          // → 403
    }
}
```

→ Đây là lý do **token sai → 401**, **token đúng nhưng thiếu role → 403**.

---

### 2.3 `@PreAuthorize` under the hood

#### Setup

```java
@Configuration
@EnableMethodSecurity   // ← bật annotation processing
public class SecurityConfig { ... }
```

`@EnableMethodSecurity` import `MethodSecurityConfiguration` → đăng ký:
- `AuthorizationManagerBeforeMethodInterceptor` cho `@PreAuthorize`
- `AuthorizationManagerAfterMethodInterceptor` cho `@PostAuthorize`
- `PreFilterAuthorizationMethodInterceptor` cho `@PreFilter`
- `PostFilterAuthorizationMethodInterceptor` cho `@PostFilter`

#### Bước 1 — AOP Proxy tạo lúc khởi động

Khi Spring scan bean và thấy `@PreAuthorize` ở method nào đó:

```java
@Service
public class OrderService {
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal")
    public Order getOrder(String userId) { ... }
}
```

Spring tạo **AOP proxy** wrap quanh bean. Khi inject `OrderService` vào controller, bạn nhận **proxy**, không phải bean gốc.

```
Controller.orderService
    ─► OrderService$$EnhancerBySpringCGLIB$$abc  (CGLIB proxy)
       │
       ├─ MethodSecurityInterceptor (advice)
       │
       └─ delegate → real OrderService instance
```

#### Bước 2 — Khi gọi method

```java
order = orderService.getOrder("u-123");
       │
       ▼
┌────────────────────────────────────────────────────────────┐
│ AuthorizationManagerBeforeMethodInterceptor.invoke()       │
│                                                            │
│  1. Lấy Authentication hiện tại:                          │
│     Authentication auth = SecurityContextHolder           │
│                            .getContext()                  │
│                            .getAuthentication();          │
│                                                            │
│  2. Build MethodInvocation context:                       │
│     - method = OrderService#getOrder                      │
│     - args = ["u-123"]                                    │
│     - target = real OrderService instance                 │
│                                                            │
│  3. PreAuthorizeAuthorizationManager.check(auth, ctx):    │
│                                                            │
│     a. Parse SpEL expression                              │
│        "hasRole('ADMIN') or #userId == authentication.principal"│
│                                                            │
│     b. Build MethodSecurityExpressionRoot:                │
│        - authentication = auth                            │
│        - principal = auth.getPrincipal()                  │
│        - hasRole(), hasAuthority(), hasPermission()       │
│        - request, returnObject (cho @PostAuthorize)       │
│                                                            │
│     c. Bind method args by name (#userId → "u-123")       │
│        Cần compile với -parameters hoặc @P("userId")      │
│                                                            │
│     d. Evaluate SpEL → AuthorizationDecision              │
│                                                            │
│  4. Quyết định:                                           │
│     - granted = true  → invoke method thật                │
│     - granted = false → throw AccessDeniedException       │
└────────────────────────────────────────────────────────────┘
       │
       ▼ (nếu granted)
   Real OrderService.getOrder() chạy
       │
       ▼
   Return Order
```

#### Bước 3 — SpEL evaluation chi tiết

`MethodSecurityExpressionRoot` extends `SecurityExpressionRoot` cung cấp các method:

```java
public abstract class SecurityExpressionRoot {
    public final boolean hasRole(String role) {
        return hasAnyRole(role);
    }

    public final boolean hasAnyRole(String... roles) {
        return hasAnyAuthorityName("ROLE_", roles);
    }

    private boolean hasAnyAuthorityName(String prefix, String... roles) {
        Set<String> authorityNames = getAuthoritySet();
        for (String role : roles) {
            String defaultedRole = (prefix == null ? role : prefix + role);
            if (authorityNames.contains(defaultedRole)) return true;
        }
        return false;
    }

    private Set<String> getAuthoritySet() {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toSet());
    }
}
```

→ `hasRole('ADMIN')` thực ra check authority có chứa `"ROLE_ADMIN"` không. Đây là lý do
scope `USER` trong POC này thành `SCOPE_USER` (prefix riêng) — nên check bằng
`hasAuthority('SCOPE_USER')`, không phải `hasRole('USER')`.

#### Bước 4 — Bind method argument vào SpEL

```java
@PreAuthorize("#userId == authentication.principal")
public Order getOrder(@P("userId") String userId) { ... }
```

`@P("userId")` hoặc compile với `-parameters` (Spring Boot mặc định) để Spring biết tên
parameter. Sau đó `DefaultMethodSecurityExpressionHandler` bind giá trị argument vào SpEL context.

#### Bước 5 — Exception flow

```java
// Method security throws:
throw new AccessDeniedException("Access is denied");
       │
       ▼ propagate up through proxy
       │
       ▼ ExceptionTranslationFilter catches it
       │
       ▼ accessDeniedHandler returns HTTP 403
```

---

### 2.4 Sơ đồ full request lifecycle

```
GET /api/orders/u-123 HTTP/1.1
Authorization: Bearer eyJ...

      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ ① SecurityContextHolderFilter                                │
│   Set up empty SecurityContext trong ThreadLocal             │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ ② JwtAuthenticationFilter                                    │
│   • Đọc "Authorization: Bearer ..."                          │
│   • JwtService.parseAndValidate(token)                       │
│     ├─ Verify HMAC signature                                 │
│     ├─ Check exp, iss                                        │
│     └─ Return Claims                                         │
│   • Build UsernamePasswordAuthenticationToken                │
│   • SecurityContextHolder.setAuthentication(auth)            │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ ③ AnonymousAuthenticationFilter                              │
│   Nếu chưa có Authentication → set Anonymous (skip vì có rồi)│
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ ④ AuthorizationFilter                                        │
│   • Lấy matched rule cho /api/orders/*                       │
│   • AuthorizationManager.check(auth, request)                │
│   • .anyRequest().authenticated() → check auth.isAuthenticated()│
│   • Granted → tiếp                                           │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ DispatcherServlet → OrderController.getOrder(userId)         │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────────┐
│ AOP Proxy: AuthorizationManagerBeforeMethodInterceptor       │
│   • SpEL: "hasRole('ADMIN') or #userId == principal"         │
│   • Evaluate với auth từ SecurityContextHolder               │
│   • Granted → invoke method thật                             │
│   • Denied → throw AccessDeniedException                     │
└──────────────────────────────────────────────────────────────┘
      │
      ▼ (granted)
   OrderService.getOrder() chạy
      │
      ▼
   Response 200 với Order JSON
```

---

### 2.5 Các điểm tinh tế (gotchas)

| Điểm | Chi tiết |
|------|----------|
| **`ThreadLocal` & async** | `SecurityContext` ở `ThreadLocal` → spawn thread mới mất context. Cần `DelegatingSecurityContextRunnable` hoặc `@Async` với `SecurityContextHolderStrategy`. |
| **Reactive (WebFlux)** | Không dùng `ThreadLocal` — dùng `Context` của Reactor. `ReactiveSecurityContextHolder.getContext()`. |
| **Filter order** | Định bởi `@Order` hoặc thứ tự config. Custom filter sai chỗ → không thấy authentication. |
| **Method security chỉ chạy trên Spring bean** | Gọi method có `@PreAuthorize` từ **cùng class** (self-invocation) → không qua proxy → **không check**. Cần `AopContext.currentProxy()` hoặc inject self. |
| **SpEL có thể nguy hiểm** | SpEL expression với user input → code execution. Đừng concat user input vào `@PreAuthorize`. |
| **`hasRole` vs `hasAuthority`** | `hasRole('X')` = `hasAuthority('ROLE_X')`. Prefix `ROLE_` bị Spring tự thêm. Token scope thường dùng `SCOPE_` prefix → dùng `hasAuthority('SCOPE_USER')`. |
| **Cache decision** | `AuthorizationManager` không cache. Mọi request đều re-evaluate. Nếu authz tốn kém (call OPA), tự cache. |
| **CGLIB vs JDK proxy** | Class không implement interface → CGLIB (subclass). `final` method → không proxy được → annotation bị bỏ qua. |

---

### 2.6 Trong POC này map vào đâu?

| Spring concept | POC file |
|----------------|----------|
| `SecurityFilterChain` config | [SecurityConfig.java](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |
| Custom auth filter | [JwtAuthenticationFilter.java](src/main/java/com/demo/authpoc/jwt/JwtAuthenticationFilter.java) |
| Token verify logic | [JwtService.java:46-53](src/main/java/com/demo/authpoc/jwt/JwtService.java) |
| `Authentication` build | [JwtAuthenticationFilter.java:43-52](src/main/java/com/demo/authpoc/jwt/JwtAuthenticationFilter.java) |
| URL-level authz | `.authorizeHttpRequests(...)` ở [SecurityConfig.java:27-37](src/main/java/com/demo/authpoc/config/SecurityConfig.java) |
| `@PreAuthorize` | **Chưa có** — POC chỉ dùng URL-level. Thêm `@EnableMethodSecurity` rồi gắn annotation vào controller method nếu muốn |

### 2.7 Ví dụ thêm `@PreAuthorize` vào POC

```java
// SecurityConfig.java
@Configuration
@EnableMethodSecurity   // ← thêm dòng này
public class SecurityConfig { ... }

// AuthController.java
@GetMapping("/me")
@PreAuthorize("hasAuthority('SCOPE_USER')")   // chú ý: SCOPE_ không phải ROLE_
public ResponseEntity<Map<String, Object>> me(Authentication auth) { ... }

// Hoặc với SpEL phức tạp:
@PreAuthorize("hasAuthority('SCOPE_ADMIN') or #userId == authentication.name")
public Order getOrder(@P("userId") String userId) { ... }

// @PostAuthorize — kiểm tra return value:
@PostAuthorize("returnObject.ownerId == authentication.name")
public Order getOrderRaw(String id) { ... }

// @PreFilter — lọc input collection:
@PreFilter("filterObject.ownerId == authentication.name")
public void deleteAll(List<Order> orders) { ... }

// @PostFilter — lọc output collection:
@PostFilter("filterObject.ownerId == authentication.name")
public List<Order> findAll() { ... }
```

---

## Phần 3 — Tham khảo nhanh

### 3.1 Các class core cần biết

| Class | Vai trò |
|-------|---------|
| `SecurityContextHolder` | ThreadLocal chứa SecurityContext |
| `SecurityContext` | Wrapper chứa `Authentication` |
| `Authentication` | Interface — principal + credentials + authorities |
| `UsernamePasswordAuthenticationToken` | Implementation phổ biến |
| `GrantedAuthority` / `SimpleGrantedAuthority` | Đơn vị quyền (string-based) |
| `AuthorizationManager<T>` | Strategy check authz (mới trong 6.x) |
| `AuthorizationDecision` | Granted/Denied + chi tiết |
| `FilterChainProxy` | Top-level filter proxy |
| `SecurityFilterChain` | Một chain matching request |
| `ExceptionTranslationFilter` | Map exception → HTTP status |
| `AuthorizationFilter` | Check URL rule (replace FilterSecurityInterceptor) |
| `MethodSecurityInterceptor` / `AuthorizationManagerBeforeMethodInterceptor` | AOP advice cho @PreAuthorize |
| `MethodSecurityExpressionRoot` | SpEL root cho method security |
| `DefaultMethodSecurityExpressionHandler` | Evaluate SpEL |

### 3.2 Annotations method security

| Annotation | Khi nào chạy | Use case |
|------------|--------------|----------|
| `@PreAuthorize` | TRƯỚC khi gọi method | Check quyền dựa trên args |
| `@PostAuthorize` | SAU khi gọi method | Check quyền dựa trên return value |
| `@PreFilter` | TRƯỚC, lọc args collection | Lọc input |
| `@PostFilter` | SAU, lọc return collection | Lọc output |
| `@Secured` | Như PreAuthorize nhưng đơn giản hơn (chỉ role list) | Legacy |
| `@RolesAllowed` | JSR-250 standard | Portable across containers |

### 3.3 Debug tips

```java
// Bật log để xem filter chain:
logging.level.org.springframework.security=DEBUG

// Hoặc lấy filter chain tại runtime:
@Autowired FilterChainProxy filterChainProxy;
filterChainProxy.getFilterChains();   // List<SecurityFilterChain>

// Check authority hiện tại:
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
auth.getAuthorities().forEach(a -> System.out.println(a.getAuthority()));
```

### 3.4 Tài liệu chính thức

- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Servlet Architecture](https://docs.spring.io/spring-security/reference/servlet/architecture.html)
- [Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [Spring Authorization Server](https://docs.spring.io/spring-authorization-server/reference/)
- [OAuth 2.0 Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)

---

## Phần 4 — Quan điểm cá nhân (cho dự án thực tế)

1. **Dùng `spring-boot-starter-oauth2-resource-server`** thay vì tự code filter như POC này
   nếu service chỉ verify JWT (không tự issue). Spring đã làm sẵn JWKS rotation, multi-issuer,
   nimbus integration.

2. **`@PreAuthorize` linh hoạt hơn URL rule** khi authz phụ thuộc resource (`#userId == principal`).
   URL rule chỉ check role/scope chung.

3. **Đừng nhồi mọi authz vào SpEL** — khi expression quá phức tạp, tách ra `PermissionEvaluator`
   hoặc gọi external authz service (OPA/SpiceDB).

4. **Test method security** với `@WithMockUser` / `@WithMockJwt`:
   ```java
   @Test
   @WithMockUser(authorities = "SCOPE_ADMIN")
   void adminCanAccess() { ... }
   ```

5. **Production**: prefer **stateless JWT verify ở Resource Server + revocation list ở Redis**
   thay vì call IdP mỗi request.

6. **mTLS + service-to-service token** quan trọng hơn JWT cho internal traffic. JWT cho user,
   mTLS cho service.

---

*Tài liệu này viết theo Spring Security 6.x / Spring Boot 3.x. API ở các phiên bản cũ hơn
có thể khác (vd: `WebSecurityConfigurerAdapter` đã deprecated, `@EnableGlobalMethodSecurity`
đã bị thay bởi `@EnableMethodSecurity`).*
