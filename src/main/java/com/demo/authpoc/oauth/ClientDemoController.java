package com.demo.authpoc.oauth;

import com.demo.authpoc.oauth.dto.TokenResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/**
 * Demo OAuth public client. Demonstrates the browser side of the PKCE handshake:
 *
 * <pre>
 *   GET /client                  -> landing
 *   GET /client/login            -> generates verifier+challenge+state, stores in session,
 *                                   redirects to /oauth/authorize
 *   GET /client/callback         -> receives ?code&state, posts to /oauth/token with verifier,
 *                                   renders the resulting token + decoded /api/me payload
 * </pre>
 */
@Controller
@RequestMapping("/client")
public class ClientDemoController {

    private static final String CLIENT_ID = "demo-client";
    private static final String REDIRECT_URI = "http://localhost:8080/client/callback";
    private static final String SCOPE = "USER";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final RestClient rest = RestClient.builder().build();

    @GetMapping({"", "/"})
    public String index() {
        return "client/index";
    }

    @GetMapping("/login")
    public RedirectView startLogin(HttpSession session) {
        String verifier = PkceUtils.newCodeVerifier();
        String challenge = PkceUtils.s256Challenge(verifier);
        String state = randomState();

        session.setAttribute("pkce_verifier", verifier);
        session.setAttribute("oauth_state", state);

        String url = UriComponentsBuilder.fromUriString("http://localhost:8080/oauth/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", SCOPE)
                .queryParam("state", state)
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .build()
                .toUriString();
        return new RedirectView(url);
    }

    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code,
                           @RequestParam("state") String state,
                           HttpSession session,
                           Model model) {

        String expectedState = (String) session.getAttribute("oauth_state");
        String verifier = (String) session.getAttribute("pkce_verifier");
        session.removeAttribute("oauth_state");
        session.removeAttribute("pkce_verifier");

        if (expectedState == null || !expectedState.equals(state)) {
            model.addAttribute("error", "CSRF/state mismatch");
            return "client/error";
        }
        if (verifier == null) {
            model.addAttribute("error", "missing PKCE verifier in session");
            return "client/error";
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", REDIRECT_URI);
        form.add("client_id", CLIENT_ID);
        form.add("code_verifier", verifier);

        TokenResponse token = rest.post()
                .uri("http://localhost:8080/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(TokenResponse.class);

        Map<String, Object> me = rest.get()
                .uri("http://localhost:8080/api/me")
                .header("Authorization", "Bearer " + token.accessToken())
                .retrieve()
                .body(Map.class);

        model.addAttribute("token", token);
        model.addAttribute("me", me);
        model.addAttribute("verifier", verifier);
        model.addAttribute("code", code);
        return "client/profile";
    }

    private static String randomState() {
        byte[] buf = new byte[16];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
