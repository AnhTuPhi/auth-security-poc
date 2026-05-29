package com.demo.authpoc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "app")
public record AppProperties(Jwt jwt, OAuth oauth) {

    public record Jwt(
            String issuer,
            String secret,
            Duration accessTokenTtl,
            Duration refreshTokenTtl
    ) {}

    public record OAuth(
            Duration authorizationCodeTtl,
            List<Client> clients
    ) {
        public record Client(
                String clientId,
                List<String> redirectUris,
                boolean requirePkce
        ) {}
    }
}
