package com.demo.authpoc.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helpers for the PKCE (RFC 7636) {@code S256} method.
 *
 * <pre>
 *   code_verifier  = base64url( random 32 bytes )                 // 43-char URL-safe
 *   code_challenge = base64url( SHA-256( code_verifier ) )
 * </pre>
 *
 * The authorization server stores the {@code code_challenge} when issuing the auth code,
 * and at the token endpoint verifies that
 * {@code base64url(SHA-256(code_verifier)) == stored code_challenge}.
 */
public final class PkceUtils {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private PkceUtils() {}

    public static String newCodeVerifier() {
        byte[] buf = new byte[32];
        RANDOM.nextBytes(buf);
        return URL_ENCODER.encodeToString(buf);
    }

    public static String s256Challenge(String verifier) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return URL_ENCODER.encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Returns true iff S256(verifier) matches the stored challenge in constant time. */
    public static boolean verify(String verifier, String challenge, String method) {
        if (!"S256".equals(method)) {
            return false; // we deliberately don't accept the deprecated "plain" method
        }
        String computed = s256Challenge(verifier);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.US_ASCII),
                challenge.getBytes(StandardCharsets.US_ASCII)
        );
    }
}
