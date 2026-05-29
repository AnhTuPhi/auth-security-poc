package com.demo.authpoc.web;

import com.demo.authpoc.jwt.AuthController;
import com.demo.authpoc.jwt.RefreshTokenException;
import com.demo.authpoc.oauth.OAuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice(basePackages = {"com.demo.authpoc.jwt", "com.demo.authpoc.oauth"})
public class ApiExceptionHandler {

    @ExceptionHandler(AuthController.BadCredentialsException.class)
    public ResponseEntity<Map<String, String>> badCreds(AuthController.BadCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_credentials", "message", ex.getMessage()));
    }

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<Map<String, String>> refreshFailed(RefreshTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_grant", "message", ex.getMessage()));
    }

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<Map<String, String>> oauth(OAuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(Map.of("error", ex.code(), "error_description", ex.getMessage()));
    }
}
