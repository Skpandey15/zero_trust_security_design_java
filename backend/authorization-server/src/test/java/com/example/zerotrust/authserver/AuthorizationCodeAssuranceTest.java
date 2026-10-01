package com.example.zerotrust.authserver;

import com.example.zerotrust.authserver.dto.AuthDtos.RegisterRequest;
import com.example.zerotrust.authserver.service.AuthService;
import com.example.zerotrust.authserver.service.TotpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The whole authorization_code flow, the way the BFF drives it: authorize,
 * sign in on the Authorization Server's page, get a code, exchange it, and read
 * the ID token. The other tests stop at "the session exists"; this one proves the
 * session can actually be turned into a token, and that the token says how the
 * user authenticated.
 *
 * <p>It exists because that gap was real: a sign-in that authenticated fine but
 * could not produce an ID token (no auth_time) passed every test that stopped
 * short of the token.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationCodeAssuranceTest {

    private static final String PASSWORD = "code-flow-pass-1234";
    private static final String REDIRECT_BASE = "http://localhost";
    private static final String REDIRECT = "http://localhost:5173/login/oauth2/code/zero-trust-web";
    private static final String CLIENT_SECRET = "local-dev-bff-secret";   // the local default

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired AuthService authService;
    @Autowired TotpService totp;

    private String account(boolean withMfa) {
        String email = "c-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        authService.register(new RegisterRequest(email, PASSWORD, "Code Flow"));
        if (withMfa) {
            String secret = authService.startMfaSetup(email).secret();
            authService.activateMfa(email, totp.generateCode(secret, totp.currentTimeStep()));
        }
        return email;
    }

    /** Runs the flow to the end and returns the decoded ID token claims. */
    private JsonNode idTokenClaims(String email, String otp, String ip) throws Exception {
        String verifier = "v".repeat(48);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        MockHttpSession session = new MockHttpSession();

        String authorizeUrl = REDIRECT_BASE + "/oauth2/authorize?response_type=code&client_id=zero-trust-web"
                + "&scope=openid%20profile&redirect_uri=" + REDIRECT + "&state=s&nonce=n"
                + "&code_challenge=" + challenge + "&code_challenge_method=S256";

        // 1. not signed in: sent to the sign-in page. A URI, not a string: MockMvc would
        //    encode the %20 a second time and the scope would stop matching.
        mvc.perform(get(URI.create(authorizeUrl)).session(session).accept("text/html"));

        // 2. sign in (with the code, where the account has two-step verification)
        var login = post("/oauth2/login").with(csrf()).session(session)
                .param("username", email).param("password", PASSWORD)
                .with(r -> { r.setRemoteAddr(ip); return r; });
        if (otp != null) login.param("otp", otp);
        MvcResult signedIn = mvc.perform(login).andReturn();
        String back = signedIn.getResponse().getRedirectedUrl();
        assertThat(back).as("sign-in succeeded").isNotNull().doesNotContain("error");

        // 3. follow the redirect exactly as a browser does: now authenticated, so a
        //    redirect carrying the code
        MvcResult authorized = mvc.perform(get(URI.create(back)).session(session).accept("text/html")).andReturn();
        String redirect = authorized.getResponse().getRedirectedUrl();
        assertThat(redirect)
                .as("authorize after sign-in: status=%d error=%s", authorized.getResponse().getStatus(),
                        authorized.getResponse().getErrorMessage())
                .startsWith(REDIRECT);
        String code = UriParam.of(redirect, "code");

        // 4. exchange the code, authenticating as the confidential client, proving PKCE
        MvcResult token = mvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                                ("zero-trust-web:" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8)))
                        .param("grant_type", "authorization_code").param("code", code)
                        .param("redirect_uri", REDIRECT).param("code_verifier", verifier))
                .andReturn();
        assertThat(token.getResponse().getStatus()).as(token.getResponse().getContentAsString()).isEqualTo(200);

        String idToken = json.readTree(token.getResponse().getContentAsString()).get("id_token").asText();
        byte[] payload = Base64.getUrlDecoder().decode(idToken.split("\\.")[1]);
        return json.readTree(new String(payload, StandardCharsets.UTF_8));
    }

    @Test
    void aPasswordSignInYieldsAnIdTokenThatSaysPasswordOnly() throws Exception {
        JsonNode claims = idTokenClaims(account(false), null, "10.20.0.1");

        assertThat(claims.get("amr")).hasSize(1);
        assertThat(claims.get("amr").get(0).asText()).isEqualTo("pwd");
        assertThat(claims.has("auth_time")).as("auth_time is present").isTrue();
    }

    @Test
    void aSignInWithTheCodeYieldsAnIdTokenThatSaysSo() throws Exception {
        String email = account(true);
        // An enabled account's secret lives only in the database - derive the code from it.
        String code = totp.generateCode(userSecret(email), totp.currentTimeStep());

        JsonNode claims = idTokenClaims(email, code, "10.20.0.2");

        assertThat(claims.get("amr")).hasSize(2);
        assertThat(claims.get("amr").toString()).contains("pwd").contains("otp");
        assertThat(claims.has("auth_time")).isTrue();
    }

    @Autowired com.example.zerotrust.authserver.repository.UserRepository users;

    private String userSecret(String email) {
        return users.findByEmailIgnoreCase(email).orElseThrow().getMfaSecret();
    }

    /** Tiny query-string reader for the redirect. */
    private static final class UriParam {
        static String of(String url, String name) {
            for (String pair : URI.create(url).getRawQuery().split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv[0].equals(name)) return java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            }
            throw new AssertionError("no " + name + " in " + url);
        }
    }
}
