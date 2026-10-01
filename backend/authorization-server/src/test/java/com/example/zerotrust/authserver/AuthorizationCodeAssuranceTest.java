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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The whole authorization_code flow, the way the BFF drives it, ending in a read
 * of the ID token. The other tests stop at "the session exists"; this one proves
 * the session can actually be turned into a token, and that the token says how
 * the user authenticated.
 *
 * <p>It exists because that gap was real: a sign-in that authenticated fine but
 * could not produce an ID token (no auth_time) passed every test that stopped
 * short of the token.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationCodeAssuranceTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired AuthService authService;
    @Autowired TotpService totp;
    @Autowired UserRepository users;

    private String account(boolean withMfa) {
        String email = "c-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        authService.register(new RegisterRequest(email, OidcTestFlow.PASSWORD, "Code Flow"));
        if (withMfa) {
            String secret = authService.startMfaSetup(email).secret();
            authService.activateMfa(email, totp.generateCode(secret, totp.currentTimeStep()));
        }
        return email;
    }

    @Test
    void aPasswordSignInYieldsAnIdTokenThatSaysPasswordOnly() throws Exception {
        OidcTestFlow flow = new OidcTestFlow(mvc, json);
        JsonNode claims = flow.claims(flow.signIn(account(false), null, "10.20.0.1", "openid profile").idToken());

        assertThat(claims.get("amr")).hasSize(1);
        assertThat(claims.get("amr").get(0).asText()).isEqualTo("pwd");
        assertThat(claims.has("auth_time")).as("auth_time is present").isTrue();
    }

    @Test
    void aSignInWithTheCodeYieldsAnIdTokenThatSaysSo() throws Exception {
        OidcTestFlow flow = new OidcTestFlow(mvc, json);
        String email = account(true);
        // An enabled account's secret lives only in the database - derive the code from it.
        String code = totp.generateCode(users.findByEmailIgnoreCase(email).orElseThrow().getMfaSecret(),
                totp.currentTimeStep());

        JsonNode claims = flow.claims(flow.signIn(email, code, "10.20.0.2", "openid profile").idToken());

        assertThat(claims.get("amr")).hasSize(2);
        assertThat(claims.get("amr").toString()).contains("pwd").contains("otp");
        assertThat(claims.has("auth_time")).isTrue();
    }
}
