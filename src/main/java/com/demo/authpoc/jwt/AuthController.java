package com.demo.authpoc.jwt;

import com.demo.authpoc.jwt.dto.LoginRequest;
import com.demo.authpoc.jwt.dto.RefreshRequest;
import com.demo.authpoc.jwt.dto.TokenResponse;
import com.demo.authpoc.user.User;
import com.demo.authpoc.user.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Demo 1: JWT access tokens + rotating refresh tokens.
 *
 * <pre>
 *   POST /api/auth/login    { username, password }   -> { accessToken, refreshToken, ... }
 *   POST /api/auth/refresh  { refreshToken }         -> { accessToken, refreshToken, ... }  (rotated)
 *   POST /api/auth/logout   { refreshToken }         -> 204
 *   GET  /api/me            Authorization: Bearer ... -> { username, scopes }
 * </pre>
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokens;

    public AuthController(UserService userService, JwtService jwtService,
                          RefreshTokenService refreshTokens) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.refreshTokens = refreshTokens;
    }

    @PostMapping("/auth/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest req) {
        User user = userService.authenticate(req.username(), req.password())
                .orElseThrow(() -> new BadCredentialsException("invalid credentials"));

        String scope = String.join(" ", user.roles());
        String access = jwtService.issueAccessToken(user.id(), user.username(), scope);
        RefreshToken refresh = refreshTokens.issueNewFamily(user.id());

        return ResponseEntity.ok(TokenResponse.bearer(
                access, refresh.id(), jwtService.getAccessTokenSeconds()
        ));
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest req) {
        RefreshToken rotated = refreshTokens.rotate(req.refreshToken());
        User user = userService.findById(rotated.userId())
                .orElseThrow(() -> new RefreshTokenException("user gone"));
        String scope = String.join(" ", user.roles());
        String access = jwtService.issueAccessToken(user.id(), user.username(), scope);

        return ResponseEntity.ok(TokenResponse.bearer(
                access, rotated.id(), jwtService.getAccessTokenSeconds()
        ));
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest req) {
        refreshTokens.revoke(req.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(Map.of(
                "username", auth.getName(),
                "authorities", auth.getAuthorities()
        ));
    }

    public static class BadCredentialsException extends RuntimeException {
        BadCredentialsException(String m) { super(m); }
    }
}
