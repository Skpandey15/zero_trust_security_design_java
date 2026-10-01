package com.example.zerotrust.authserver;

import com.example.zerotrust.authserver.dto.AuthDtos.RegisterRequest;
import com.example.zerotrust.authserver.service.AuthService;
import com.example.zerotrust.authserver.service.TotpService;
import com.example.zerotrust.authserver.web.AccountMfaController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Two-step verification enrolment is hosted on the Authorization Server (the
 * secret is the factor and must not reach the SPA), and it demands RECENT
 * authentication (ADR-SEC-004).
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccountMfaPageTest {

    @Autowired MockMvc mvc;
    @Autowired AuthService authService;
    @Autowired TotpService totp;

    private String newAccount() {
        String email = "a-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        authService.register(new RegisterRequest(email, "account-page-pass-1234", "Account"));
        return email;
    }

    private static MockHttpSession signedInAt(Instant when) {
        MockHttpSession session = new MockHttpSession();
        if (when != null) session.setAttribute(AccountMfaController.AUTH_TIME, when);
        return session;
    }

    @Test
    void anonymousVisitorIsSentToSignIn() throws Exception {
        mvc.perform(get("/oauth2/account/mfa").accept("text/html"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/oauth2/login")));
    }

    @Test
    void aStaleSessionMustSignInAgainBeforeChangingAFactor() throws Exception {
        String email = newAccount();

        mvc.perform(get("/oauth2/account/mfa").with(user(email))
                        .session(signedInAt(Instant.now().minus(Duration.ofMinutes(30)))))
                .andExpect(redirectedUrl("/oauth2/login?reauth"));
    }

    @Test
    void aSessionWithNoSignInTimestampCountsAsStale() throws Exception {
        String email = newAccount();

        mvc.perform(get("/oauth2/account/mfa").with(user(email)).session(signedInAt(null)))
                .andExpect(redirectedUrl("/oauth2/login?reauth"));
    }

    @Test
    void aRecentSessionSeesTheSetupOffer() throws Exception {
        String email = newAccount();

        mvc.perform(get("/oauth2/account/mfa").with(user(email)).session(signedInAt(Instant.now())))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/oauth2/account/mfa/start")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void startingSetupRequiresACsrfToken() throws Exception {
        String email = newAccount();

        mvc.perform(post("/oauth2/account/mfa/start").with(user(email)).session(signedInAt(Instant.now())))
                .andExpect(status().isForbidden());
        assertThat(authService.pendingMfaSetup(email)).isEmpty();
    }

    @Test
    void theFullEnrolmentTurnsTwoStepOnAndEndsTheSession() throws Exception {
        String email = newAccount();
        MockHttpSession session = signedInAt(Instant.now());

        // start: the page shows the secret, and the account has a pending (unconfirmed) factor
        MvcResult started = mvc.perform(post("/oauth2/account/mfa/start").with(csrf()).with(user(email)).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("otpauth://totp/")))
                .andReturn();
        String secret = authService.pendingMfaSetup(email).orElseThrow().secret();
        assertThat(started.getResponse().getContentAsString()).contains(secret);
        assertThat(authService.isMfaEnabled(email)).as("not on until a code is confirmed").isFalse();

        // a wrong code does not turn it on, and the secret is shown again to retry
        mvc.perform(post("/oauth2/account/mfa/activate").with(csrf()).with(user(email)).session(session)
                        .param("code", "000000"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("did not match")))
                .andExpect(content().string(containsString(secret)));
        assertThat(authService.isMfaEnabled(email)).isFalse();

        // the right code turns it on and signs the user out of this session
        mvc.perform(post("/oauth2/account/mfa/activate").with(csrf()).with(user(email)).session(session)
                        .param("code", totp.generateCode(secret, totp.currentTimeStep())))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("signed out")))
                .andExpect(content().string(not(containsString(secret))));
        assertThat(authService.isMfaEnabled(email)).isTrue();
        assertThat(session.isInvalid()).as("session ended: the next sign-in must prove the factor").isTrue();
    }

    @Test
    void anAccountThatAlreadyHasTwoStepCannotBeReEnrolledFromThisPage() throws Exception {
        String email = newAccount();
        String secret = authService.startMfaSetup(email).secret();
        authService.activateMfa(email, totp.generateCode(secret, totp.currentTimeStep()));

        // Re-enrolling would silently replace the factor; it needs an explicit disable first.
        mvc.perform(post("/oauth2/account/mfa/start").with(csrf()).with(user(email)).session(signedInAt(Instant.now())))
                .andExpect(redirectedUrl("/oauth2/account/mfa"));
        assertThat(authService.pendingMfaSetup(email)).isEmpty();
    }
}
