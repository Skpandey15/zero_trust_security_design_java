package com.example.zerotrust.authserver;

import com.example.zerotrust.authserver.dto.AuthDtos.RegisterRequest;
import com.example.zerotrust.authserver.repository.UserRepository;
import com.example.zerotrust.authserver.service.AuthService;
import com.example.zerotrust.authserver.service.TotpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ADR-SEC-016. The BFF swaps its login token for one aimed at a single API.
 * Exchange must only ever narrow: the result is audience-restricted to an
 * allow-listed API, down-scoped, an RFC 9068 at+jwt, and there is no fallback to
 * a broader token when anything is wrong.
 */
@SpringBootTest
@AutoConfigureMockMvc
class TokenExchangeTest {

    private static final String API = "zero-trust-api";

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired AuthService authService;
    @Autowired TotpService totp;
    @Autowired UserRepository users;

    private OidcTestFlow flow() { return new OidcTestFlow(mvc, json); }

    private String account(boolean withMfa) {
        String email = "x-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        authService.register(new RegisterRequest(email, OidcTestFlow.PASSWORD, "Exchange"));
        if (withMfa) {
            String secret = authService.startMfaSetup(email).secret();
            authService.activateMfa(email, totp.generateCode(secret, totp.currentTimeStep()));
        }
        return email;
    }

    private String loginToken(String email, String otp, String ip, String scope) throws Exception {
        return flow().signIn(email, otp, ip, scope).accessToken();
    }

    @Test
    void exchangeYieldsAnAudienceRestrictedDownScopedAtJwt() throws Exception {
        OidcTestFlow flow = flow();
        String email = account(false);
        String login = loginToken(email, null, "10.30.0.1", OidcTestFlow.ALL_SCOPES);

        MvcResult result = flow.exchangeAsBff(login, API, "documents.read");

        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        String exchanged = flow.body(result).get("access_token").asText();
        JsonNode header = flow.header(exchanged);
        JsonNode claims = flow.claims(exchanged);

        assertThat(header.get("typ").asText()).as("RFC 9068").isEqualTo("at+jwt");
        // JWT allows a single audience as a string or a one-element array; accept either.
        java.util.Set<String> audience = new java.util.HashSet<>();
        if (claims.get("aud").isArray()) claims.get("aud").forEach(a -> audience.add(a.asText()));
        else audience.add(claims.get("aud").asText());
        assertThat(audience).as("audience is the API, and only the API").containsExactly("zero-trust-api");
        assertThat(claims.get("client_id").asText()).isEqualTo("zero-trust-web");
        assertThat(claims.get("scope").toString()).as("down-scoped to the one asked for").contains("documents.read")
                .doesNotContain("documents.write").doesNotContain("documents.approve").doesNotContain("openid");
        assertThat(claims.get("uid").asLong()).isEqualTo(users.findByEmailIgnoreCase(email).orElseThrow().getId());
        assertThat(claims.get("amr").get(0).asText()).isEqualTo("pwd");
        long lifetime = claims.get("exp").asLong() - claims.get("iat").asLong();
        assertThat(lifetime).as("short-lived: revocation relies on TTL").isLessThanOrEqualTo(300);
    }

    @Test
    void theSecondFactorCarriesAcrossTheExchange() throws Exception {
        OidcTestFlow flow = flow();
        String email = account(true);
        String code = totp.generateCode(users.findByEmailIgnoreCase(email).orElseThrow().getMfaSecret(),
                totp.currentTimeStep());
        String login = loginToken(email, code, "10.30.0.2", OidcTestFlow.ALL_SCOPES);

        JsonNode claims = flow.claims(flow.body(flow.exchangeAsBff(login, API, "documents.approve")).get("access_token").asText());

        // The Resource Server demands this for a sensitive operation, so it must survive.
        assertThat(claims.get("amr").toString()).contains("pwd").contains("otp");
    }

    @Test
    void exchangeCannotWidenScope() throws Exception {
        OidcTestFlow flow = flow();
        // The login token only ever held documents.read ...
        String login = loginToken(account(false), null, "10.30.0.3", "openid profile documents.read");

        // ... so no exchange can conjure documents.approve out of it.
        MvcResult result = flow.exchangeAsBff(login, API, "documents.approve");

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(flow.body(result).get("error").asText()).isEqualTo("invalid_scope");
    }

    @Test
    void anAudienceOutsideTheAllowListIsRefused() throws Exception {
        OidcTestFlow flow = flow();
        String login = loginToken(account(false), null, "10.30.0.4", OidcTestFlow.ALL_SCOPES);

        MvcResult result = flow.exchangeAsBff(login, "payments-api", "documents.read");

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(flow.body(result).get("error").asText()).isEqualTo("invalid_target");
    }

    @Test
    void anExchangeNamingNoAudienceIsRefusedRatherThanDefaultedToTheClient() throws Exception {
        OidcTestFlow flow = flow();
        String login = loginToken(account(false), null, "10.30.0.5", OidcTestFlow.ALL_SCOPES);

        MvcResult result = flow.exchangeAsBff(login, null, "documents.read");

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void aMixedListWithOneForbiddenAudienceIsRefusedWholesale() throws Exception {
        OidcTestFlow flow = flow();
        String login = loginToken(account(false), null, "10.30.0.6", OidcTestFlow.ALL_SCOPES);

        var request = org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/oauth2/token")
                .header("Authorization", "Basic " + java.util.Base64.getEncoder().encodeToString(
                        ("zero-trust-web:" + OidcTestFlow.CLIENT_SECRET).getBytes()))
                .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .param("subject_token", login)
                .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                .param("audience", API).param("audience", "payments-api")
                .param("scope", "documents.read");

        assertThat(mvc.perform(request).andReturn().getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void aClientNotRegisteredForExchangeCannotUseIt() throws Exception {
        OidcTestFlow flow = flow();
        String login = loginToken(account(false), null, "10.30.0.7", OidcTestFlow.ALL_SCOPES);

        // 'service-account' is a client_credentials client: not allowed this grant type.
        MvcResult result = flow.exchange("service-account", "service-secret", login, API, "documents.read");

        assertThat(result.getResponse().getStatus()).isIn(400, 401);
        assertThat(result.getResponse().getContentAsString()).doesNotContain("access_token");
    }

    @Test
    void exchangeNeedsClientAuthentication() throws Exception {
        OidcTestFlow flow = flow();
        String login = loginToken(account(false), null, "10.30.0.8", OidcTestFlow.ALL_SCOPES);

        MvcResult result = flow.exchange("zero-trust-web", "wrong-secret", login, API, "documents.read");

        assertThat(result.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void aGarbageSubjectTokenIsRefused() throws Exception {
        MvcResult result = flow().exchangeAsBff("not-a-token", API, "documents.read");

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(result.getResponse().getContentAsString()).doesNotContain("access_token");
    }
}
