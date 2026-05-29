package com.demo.authpoc.oauth;

import org.springframework.http.HttpStatus;

public class OAuthException extends RuntimeException {
    private final String code;
    private final HttpStatus status;

    public OAuthException(HttpStatus status, String code, String message) {
        super(message);
        this.code = code;
        this.status = status;
    }

    public static OAuthException invalidRequest(String msg) {
        return new OAuthException(HttpStatus.BAD_REQUEST, "invalid_request", msg);
    }
    public static OAuthException invalidGrant(String msg) {
        return new OAuthException(HttpStatus.BAD_REQUEST, "invalid_grant", msg);
    }
    public static OAuthException invalidClient(String msg) {
        return new OAuthException(HttpStatus.UNAUTHORIZED, "invalid_client", msg);
    }

    public String code() { return code; }
    public HttpStatus status() { return status; }
}
