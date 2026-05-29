package com.demo.authpoc;

import com.demo.authpoc.oauth.PkceUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PkceUtilsTest {

    @Test
    void rfc7636AppendixBVector() {
        // From RFC 7636 Appendix B.
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assertEquals(expected, PkceUtils.s256Challenge(verifier));
        assertTrue(PkceUtils.verify(verifier, expected, "S256"));
    }

    @Test
    void rejectsPlainMethod() {
        String verifier = PkceUtils.newCodeVerifier();
        String challenge = PkceUtils.s256Challenge(verifier);
        assertFalse(PkceUtils.verify(verifier, challenge, "plain"));
    }

    @Test
    void wrongVerifierFails() {
        String challenge = PkceUtils.s256Challenge(PkceUtils.newCodeVerifier());
        assertFalse(PkceUtils.verify(PkceUtils.newCodeVerifier(), challenge, "S256"));
    }
}
