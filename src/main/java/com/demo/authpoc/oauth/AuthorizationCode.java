package com.demo.authpoc.oauth;

import java.time.Instant;

public final class AuthorizationCode {

    private final String code;
    private final String clientId;
    private final String userId;
    private final String redirectUri;
    private final String scope;
    private final String codeChallenge;
    private final String codeChallengeMethod;
    private final Instant expiresAt;
    private volatile boolean consumed;

    public AuthorizationCode(String code, String clientId, String userId, String redirectUri,
                             String scope, String codeChallenge, String codeChallengeMethod,
                             Instant expiresAt) {
        this.code = code;
        this.clientId = clientId;
        this.userId = userId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiresAt = expiresAt;
    }

    public String code() { return code; }
    public String clientId() { return clientId; }
    public String userId() { return userId; }
    public String redirectUri() { return redirectUri; }
    public String scope() { return scope; }
    public String codeChallenge() { return codeChallenge; }
    public String codeChallengeMethod() { return codeChallengeMethod; }
    public Instant expiresAt() { return expiresAt; }
    public boolean consumed() { return consumed; }

    void markConsumed() { this.consumed = true; }
    public boolean isExpired() { return Instant.now().isAfter(expiresAt); }
}
