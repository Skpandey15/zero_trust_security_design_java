package com.example.zerotrust.authserver;

import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Drives the real authorization_code flow the way the BFF does - authorize, sign
 * in on the Authorization Server's page, exchange the code with PKCE - and the
 * RFC 8693 token exchange that follows. Shared so the tests that need a genuine
 * token do not each re-implement it.
 */
final class OidcTestFlow {

    static final String PASSWORD = "code-flow-pass-1234";
    static final String REDIRECT = "http://localhost:5173/login/oauth2/code/zero-trust-web";
    static final String CLIENT_SECRET = "local-dev-bff-secret";   // the local default
    static final String ALL_SCOPES = "openid profile documents.read documents.write documents.approve";

    record Tokens(String accessToken, String idToken) {}

    private final MockMvc mvc;
    private final ObjectMapper json;

    OidcTestFlow(MockMvc mvc, ObjectMapper json) {
        this.mvc = mvc;
        this.json = json;
    }

    /** Sign in and return the login tokens, requesting {@code scope}. */
    Tokens signIn(String email, String otp, String ip, String scope) throws Exception {
        String verifier = "v".repeat(48);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MockHttpSession session = new MockHttpSession();

        String authorizeUrl = "http://localhost/oauth2/authorize?response_type=code&client_id=zero-trust-web"
                + "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8).replace("+", "%20")
                + "&redirect_uri=" + REDIRECT + "&state=s&nonce=n"
                + "&code_challenge=" + challenge + "&code_challenge_method=S256";

        // 1. not signed in: sent to the sign-in page. A URI, not a string: MockMvc would
        //    encode the %20 a second time and the scope would stop matching.
        mvc.perform(get(URI.create(authorizeUrl)).session(session).accept("text/html"));

        // 2. sign in (with the code, where the account has two-step verification)
        var login = post("/oauth2/login").with(csrf()).session(session)
                .param("username", email).param("password", PASSWORD)
                .with(r -> { r.setRemoteAddr(ip); return r; });
        if (otp != null) login.param("otp", otp);
        String back = mvc.perform(login).andReturn().getResponse().getRedirectedUrl();
        assertThat(back).as("sign-in succeeded").isNotNull().doesNotContain("error");

        // 3. follow the redirect exactly as a browser does: now authenticated, so a
        //    redirect carrying the code
        MvcResult authorized = mvc.perform(get(URI.create(back)).session(session).accept("text/html")).andReturn();
        String redirect = authorized.getResponse().getRedirectedUrl();
        assertThat(redirect)
                .as("authorize after sign-in: status=%d error=%s", authorized.getResponse().getStatus(),
                        authorized.getResponse().getErrorMessage())
                .startsWith(REDIRECT);
        String code = queryParam(redirect, "code");

        // 4. exchange the code, authenticating as the confidential client, proving PKCE
        MvcResult token = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("zero-trust-web", CLIENT_SECRET))
                        .param("grant_type", "authorization_code").param("code", code)
                        .param("redirect_uri", REDIRECT).param("code_verifier", verifier))
                .andReturn();
        assertThat(token.getResponse().getStatus()).as(token.getResponse().getContentAsString()).isEqualTo(200);

        JsonNode body = json.readTree(token.getResponse().getContentAsString());
        return new Tokens(body.get("access_token").asText(), body.get("id_token").asText());
    }

    /** RFC 8693: swap a login access token for one aimed at an API. */
    MvcResult exchange(String clientId, String clientSecret, String subjectToken, String audience, String scope)
            throws Exception {
        var request = post("/oauth2/token")
                .header("Authorization", basic(clientId, clientSecret))
                .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .param("subject_token", subjectToken)
                .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        if (audience != null) request.param("audience", audience);
        if (scope != null) request.param("scope", scope);
        return mvc.perform(request).andReturn();
    }

    MvcResult exchangeAsBff(String subjectToken, String audience, String scope) throws Exception {
        return exchange("zero-trust-web", CLIENT_SECRET, subjectToken, audience, scope);
    }

    JsonNode claims(String jwt) throws Exception {
        return json.readTree(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8));
    }

    JsonNode header(String jwt) throws Exception {
        return json.readTree(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[0]), StandardCharsets.UTF_8));
    }

    JsonNode body(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static String queryParam(String url, String name) {
        for (String pair : URI.create(url).getRawQuery().split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv[0].equals(name)) return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
        }
        throw new AssertionError("no " + name + " in " + url);
    }
}
