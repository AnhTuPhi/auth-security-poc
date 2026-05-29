package com.demo.authpoc;

import com.demo.authpoc.config.AppProperties;
import com.demo.authpoc.jwt.RefreshToken;
import com.demo.authpoc.jwt.RefreshTokenException;
import com.demo.authpoc.jwt.RefreshTokenService;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RefreshTokenRotationTest {

    private RefreshTokenService newService() {
        AppProperties props = new AppProperties(
                new AppProperties.Jwt("test", "x".repeat(40), Duration.ofMinutes(5), Duration.ofDays(1)),
                new AppProperties.OAuth(Duration.ofSeconds(60), List.of())
        );
        return new RefreshTokenService(props);
    }

    @Test
    void rotationMintsNewTokenAndBurnsTheOld() {
        RefreshTokenService svc = newService();
        RefreshToken t1 = svc.issueNewFamily("alice");
        RefreshToken t2 = svc.rotate(t1.id());

        assertNotEquals(t1.id(), t2.id());
        assertEquals(t1.familyId(), t2.familyId());
        assertTrue(t1.used());

        // Reusing the original is rejected and revokes the whole family.
        assertThrows(RefreshTokenException.class, () -> svc.rotate(t1.id()));
        assertThrows(RefreshTokenException.class, () -> svc.rotate(t2.id()),
                "successor should be revoked after reuse detection");
    }

    @Test
    void unknownTokenIsRejected() {
        RefreshTokenService svc = newService();
        assertThrows(RefreshTokenException.class, () -> svc.rotate("not-a-real-token"));
    }
}
