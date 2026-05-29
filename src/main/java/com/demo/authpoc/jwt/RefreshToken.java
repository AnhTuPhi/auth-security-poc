package com.demo.authpoc.jwt;

import java.time.Instant;

/**
 * A stored refresh token record.
 *
 * <p>Refresh token rotation: each {@code /refresh} mints a brand-new token in the same
 * {@code familyId} chain and marks the parent as {@code used}. If a {@code used} token is
 * ever presented again it means the token was leaked — the whole {@code familyId} is revoked.
 */
public final class RefreshToken {

    private final String id;          // opaque token value (also the lookup key)
    private final String familyId;    // shared across all rotations from one login
    private final String userId;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile boolean used;
    private volatile boolean revoked;

    public RefreshToken(String id, String familyId, String userId,
                        Instant issuedAt, Instant expiresAt) {
        this.id = id;
        this.familyId = familyId;
        this.userId = userId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String id() { return id; }
    public String familyId() { return familyId; }
    public String userId() { return userId; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public boolean used() { return used; }
    public boolean revoked() { return revoked; }

    void markUsed() { this.used = true; }
    void revoke() { this.revoked = true; }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isActive() {
        return !used && !revoked && !isExpired();
    }
}
