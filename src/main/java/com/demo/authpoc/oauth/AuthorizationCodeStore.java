package com.demo.authpoc.oauth;

import com.demo.authpoc.config.AppProperties;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AuthorizationCodeStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, AuthorizationCode> byCode = new ConcurrentHashMap<>();
    private final long ttlSeconds;

    public AuthorizationCodeStore(AppProperties props) {
        this.ttlSeconds = props.oauth().authorizationCodeTtl().toSeconds();
    }

    public AuthorizationCode issue(String clientId, String userId, String redirectUri,
                                   String scope, String codeChallenge, String method) {
        String code = newCode();
        AuthorizationCode auth = new AuthorizationCode(
                code, clientId, userId, redirectUri, scope,
                codeChallenge, method, Instant.now().plusSeconds(ttlSeconds)
        );
        byCode.put(code, auth);
        return auth;
    }

    public Optional<AuthorizationCode> find(String code) {
        return Optional.ofNullable(byCode.get(code));
    }

    /** Atomically consume the code, returning it iff still active. */
    public AuthorizationCode consume(String code) {
        AuthorizationCode c = byCode.get(code);
        if (c == null) throw OAuthException.invalidGrant("unknown code");
        if (c.consumed()) {
            // Replay defence — code already used. In a real server we'd also revoke any
            // tokens issued from this code's session.
            throw OAuthException.invalidGrant("code already used");
        }
        if (c.isExpired()) throw OAuthException.invalidGrant("code expired");
        c.markConsumed();
        return c;
    }

    private static String newCode() {
        byte[] buf = new byte[24];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
