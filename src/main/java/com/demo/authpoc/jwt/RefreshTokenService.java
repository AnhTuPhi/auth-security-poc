package com.demo.authpoc.jwt;

import com.demo.authpoc.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory refresh token store implementing rotation + reuse detection.
 *
 * <p>Rules:
 * <ul>
 *   <li>Every issuance produces a single-use token.</li>
 *   <li>A successful {@code rotate(...)} marks the consumed token as used and mints its successor
 *       in the same family.</li>
 *   <li>If a token that has already been used is presented to {@code rotate(...)}, the entire
 *       family is revoked — this is the textbook signal that the token has been stolen.</li>
 * </ul>
 *
 * <p>A production implementation would persist these records (e.g. Postgres, Redis) and store
 * only a hash of the token value, never the raw value.
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, RefreshToken> tokensById = new ConcurrentHashMap<>();
    private final long ttlSeconds;

    public RefreshTokenService(AppProperties props) {
        this.ttlSeconds = props.jwt().refreshTokenTtl().toSeconds();
    }

    /** Mint a brand-new refresh token starting a new family (called on initial login). */
    public RefreshToken issueNewFamily(String userId) {
        return mint(userId, UUID.randomUUID().toString());
    }

    /**
     * Validate the presented token and rotate it: caller gets a fresh token,
     * the presented one is invalidated.
     *
     * @throws RefreshTokenException if the presented token is unknown, expired, revoked,
     *         or has already been used (in which case the whole family is revoked).
     */
    public RefreshToken rotate(String presented) {
        RefreshToken existing = tokensById.get(presented);

        if (existing == null) {
            log.warn("Refresh attempt with unknown token");
            throw new RefreshTokenException("Unknown refresh token");
        }

        if (existing.revoked()) {
            log.warn("Refresh attempt with revoked token family={}", existing.familyId());
            throw new RefreshTokenException("Refresh token revoked");
        }

        if (existing.isExpired()) {
            throw new RefreshTokenException("Refresh token expired");
        }

        if (existing.used()) {
            // Reuse detected — assume theft and burn down the whole family.
            log.error("REUSE DETECTED on token family={}, user={}. Revoking family.",
                    existing.familyId(), existing.userId());
            revokeFamily(existing.familyId());
            throw new RefreshTokenException("Refresh token reuse detected; family revoked");
        }

        existing.markUsed();
        return mint(existing.userId(), existing.familyId());
    }

    /** Idempotent logout: revoke just this one token. */
    public void revoke(String tokenId) {
        RefreshToken t = tokensById.get(tokenId);
        if (t != null) {
            t.revoke();
        }
    }

    public void revokeFamily(String familyId) {
        tokensById.values().stream()
                .filter(t -> t.familyId().equals(familyId))
                .forEach(RefreshToken::revoke);
    }

    private RefreshToken mint(String userId, String familyId) {
        String id = newOpaqueToken();
        Instant now = Instant.now();
        RefreshToken token = new RefreshToken(
                id, familyId, userId, now, now.plusSeconds(ttlSeconds)
        );
        tokensById.put(id, token);
        return token;
    }

    private static String newOpaqueToken() {
        byte[] buf = new byte[32];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
