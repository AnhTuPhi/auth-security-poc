package com.demo.authpoc.oauth;

import com.demo.authpoc.config.AppProperties;
import com.demo.authpoc.jwt.JwtService;
import com.demo.authpoc.oauth.dto.TokenResponse;
import com.demo.authpoc.user.User;
import com.demo.authpoc.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Authorization server: implements the {@code authorization_code} grant with mandatory PKCE.
 *
 * <pre>
 *   GET  /oauth/authorize    -> renders login + consent form
 *   POST /oauth/authorize    -> validates creds + redirects with ?code=...&state=...
 *   POST /oauth/token        -> exchanges code+code_verifier for an access token
 * </pre>
 */
@Controller
@RequestMapping("/oauth")
public class AuthorizationServerController {

    private final ClientRegistry clients;
    private final AuthorizationCodeStore codes;
    private final UserService users;
    private final JwtService jwt;

    public AuthorizationServerController(ClientRegistry clients, AuthorizationCodeStore codes,
                                         UserService users, JwtService jwt) {
        this.clients = clients;
        this.codes = codes;
        this.users = users;
        this.jwt = jwt;
    }

    @GetMapping("/authorize")
    public String authorizeForm(@RequestParam("response_type") String responseType,
                                @RequestParam("client_id") String clientId,
                                @RequestParam("redirect_uri") String redirectUri,
                                @RequestParam(value = "scope", required = false) String scope,
                                @RequestParam(value = "state", required = false) String state,
                                @RequestParam("code_challenge") String codeChallenge,
                                @RequestParam(value = "code_challenge_method", defaultValue = "S256") String method,
                                Model model) {

        if (!"code".equals(responseType)) {
            throw OAuthException.invalidRequest("response_type must be 'code'");
        }
        AppProperties.OAuth.Client client = clients.require(clientId);
        if (!client.redirectUris().contains(redirectUri)) {
            throw OAuthException.invalidRequest("redirect_uri not registered for client");
        }
        if (client.requirePkce() && (codeChallenge == null || codeChallenge.isBlank())) {
            throw OAuthException.invalidRequest("PKCE code_challenge is required");
        }
        if (!"S256".equals(method)) {
            throw OAuthException.invalidRequest("only S256 code_challenge_method is supported");
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", redirectUri);
        model.addAttribute("scope", scope == null ? "" : scope);
        model.addAttribute("state", state == null ? "" : state);
        model.addAttribute("codeChallenge", codeChallenge);
        model.addAttribute("codeChallengeMethod", method);
        return "authorize";
    }

    @PostMapping(value = "/authorize", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public RedirectView authorizeSubmit(@RequestParam("username") String username,
                                        @RequestParam("password") String password,
                                        @RequestParam("client_id") String clientId,
                                        @RequestParam("redirect_uri") String redirectUri,
                                        @RequestParam(value = "scope", required = false) String scope,
                                        @RequestParam(value = "state", required = false) String state,
                                        @RequestParam("code_challenge") String codeChallenge,
                                        @RequestParam("code_challenge_method") String method) {

        AppProperties.OAuth.Client client = clients.require(clientId);
        if (!client.redirectUris().contains(redirectUri)) {
            throw OAuthException.invalidRequest("redirect_uri not registered for client");
        }

        User user = users.authenticate(username, password)
                .orElseThrow(() -> OAuthException.invalidGrant("bad credentials"));

        AuthorizationCode authCode = codes.issue(
                clientId, user.id(), redirectUri,
                scope == null ? "" : scope, codeChallenge, method
        );

        String location = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("code", authCode.code())
                .queryParamIfPresent("state",
                        state == null || state.isBlank() ? java.util.Optional.empty() : java.util.Optional.of(state))
                .build(true)
                .toUriString();
        return new RedirectView(location);
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public ResponseEntity<TokenResponse> token(@RequestParam("grant_type") String grantType,
                                               @RequestParam("code") String code,
                                               @RequestParam("redirect_uri") String redirectUri,
                                               @RequestParam("client_id") String clientId,
                                               @RequestParam("code_verifier") String codeVerifier,
                                               HttpServletRequest request) {

        if (!"authorization_code".equals(grantType)) {
            throw OAuthException.invalidRequest("unsupported grant_type");
        }

        AuthorizationCode auth = codes.consume(code);

        if (!auth.clientId().equals(clientId)) {
            throw OAuthException.invalidGrant("client_id mismatch");
        }
        if (!auth.redirectUri().equals(redirectUri)) {
            throw OAuthException.invalidGrant("redirect_uri mismatch");
        }
        if (!PkceUtils.verify(codeVerifier, auth.codeChallenge(), auth.codeChallengeMethod())) {
            throw OAuthException.invalidGrant("PKCE verification failed");
        }

        User user = users.findById(auth.userId())
                .orElseThrow(() -> OAuthException.invalidGrant("user gone"));
        String accessToken = jwt.issueAccessToken(user.id(), user.username(), auth.scope());

        return ResponseEntity.ok(new TokenResponse(
                accessToken, "Bearer", jwt.getAccessTokenSeconds(), auth.scope()
        ));
    }
}
