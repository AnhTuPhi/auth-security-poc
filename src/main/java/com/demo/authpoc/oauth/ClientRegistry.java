package com.demo.authpoc.oauth;

import com.demo.authpoc.config.AppProperties;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class ClientRegistry {

    private final Map<String, AppProperties.OAuth.Client> byId;

    public ClientRegistry(AppProperties props) {
        this.byId = props.oauth().clients().stream()
                .collect(Collectors.toUnmodifiableMap(
                        AppProperties.OAuth.Client::clientId, c -> c
                ));
    }

    public Optional<AppProperties.OAuth.Client> find(String clientId) {
        return Optional.ofNullable(byId.get(clientId));
    }

    public AppProperties.OAuth.Client require(String clientId) {
        return find(clientId).orElseThrow(() ->
                OAuthException.invalidClient("unknown client: " + clientId));
    }
}
