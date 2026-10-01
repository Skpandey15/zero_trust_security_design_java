package com.example.zerotrust.authserver;

import com.example.zerotrust.authserver.service.AuthService;
import com.example.zerotrust.authserver.service.TotpService;
import com.example.zerotrust.authserver.dto.AuthDtos.RegisterRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ADR-SEC-004: password-only login is refused where MFA is enrolled - on EVERY
 * door, not just the token API. The interactive sign-in page used to accept a
 * password alone for an account that had switched two-step verification on,
 * which made the second factor decorative.
 */
@SpringBootTest
@AutoConfigureMockMvc
class InteractiveMfaLoginTest {

    private static final String PASSWORD = "interactive-pass-1234";

    @Autowired MockMvc mvc;
    @Autowired AuthService authService;
    @Autowired TotpService totp;

    /** A fresh account, optionally with two-step verification on. Returns {email, secret-or-null}. */
    private String[] account(boolean withMfa) {
        String email = "i-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        authService.register(new RegisterRequest(email, PASSWORD, "Interactive"));
        String secret = null;
        if (withMfa) {
            secret = authService.startMfaSetup(email).secret();
            authService.activateMfa(email, totp.generateCode(secret, totp.currentTimeStep()));
        }
        return new String[] {email, secret};
    }

    private MockHttpServletRequestBuilder signIn(String email, String password, String otp, String ip) {
        MockHttpServletRequestBuilder req = post("/oauth2/login").with(csrf())
                .param("username", email).param("password", password)
                .with(r -> { r.setRemoteAddr(ip); return r; });
        if (otp != null) req.param("otp", otp);
        return req;
    }

    private String currentCode(String secret) {
        return totp.generateCode(secret, totp.currentTimeStep());
    }

    private static Authentication authenticationIn(MvcResult result) {
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        if (session == null) return null;
        SecurityContext ctx = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        return ctx == null ? null : ctx.getAuthentication();
    }

    private static List<String> authorities(Authentication a) {
        return a.getAuthorities().stream().map(org.springframework.security.core.GrantedAuthority::getAuthority).toList();
    }

    @Test
    void passwordAloneIsRefusedWhenTwoStepIsOn() throws Exception {
        String[] a = account(true);

        MvcResult result = mvc.perform(signIn(a[0], PASSWORD, null, "10.10.0.1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/login?error"))
                .andReturn();

        assertThat(authenticationIn(result)).as("no session was established").isNull();
    }

    @Test
    void passwordPlusValidCodeSignsInAndRecordsBothFactors() throws Exception {
        String[] a = account(true);

        MvcResult result = mvc.perform(signIn(a[0], PASSWORD, currentCode(a[1]), "10.10.0.2"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).doesNotContain("error");
        assertThat(authorities(authenticationIn(result))).contains("FACTOR_PASSWORD", "FACTOR_TOTP");
    }

    @Test
    void aReplayedCodeIsRefused() throws Exception {
        String[] a = account(true);
        String code = currentCode(a[1]);

        mvc.perform(signIn(a[0], PASSWORD, code, "10.10.0.3")).andExpect(status().is3xxRedirection());

        // The same code, inside its own validity window, must not work twice.
        mvc.perform(signIn(a[0], PASSWORD, code, "10.10.0.3"))
                .andExpect(redirectedUrl("/oauth2/login?error"));
    }

    @Test
    void aWrongCodeIsRefusedEvenWithTheRightPassword() throws Exception {
        String[] a = account(true);

        mvc.perform(signIn(a[0], PASSWORD, "000000", "10.10.0.4"))
                .andExpect(redirectedUrl("/oauth2/login?error"));
    }

    @Test
    void repeatedFailuresLockTheAccountOnThisDoorToo() throws Exception {
        String[] a = account(true);

        for (int i = 0; i < 5; i++) {
            mvc.perform(signIn(a[0], PASSWORD, "000000", "10.10.0.5"));
        }

        // Locked: even the correct password and a valid code are now refused.
        mvc.perform(signIn(a[0], PASSWORD, currentCode(a[1]), "10.10.0.6"))
                .andExpect(redirectedUrl("/oauth2/login?error"));
    }

    @Test
    void anAccountWithoutTwoStepSignsInWithPasswordAlone() throws Exception {
        String[] a = account(false);

        MvcResult result = mvc.perform(signIn(a[0], PASSWORD, null, "10.10.0.7"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl()).doesNotContain("error");
        // Password assurance only - and the session says so.
        assertThat(authorities(authenticationIn(result)))
                .contains("FACTOR_PASSWORD").doesNotContain("FACTOR_TOTP");
    }

    @Test
    void anUnknownUserFailsExactlyLikeAWrongPassword() throws Exception {
        String[] a = account(false);

        mvc.perform(signIn("nobody-" + UUID.randomUUID() + "@example.com", PASSWORD, null, "10.10.0.8"))
                .andExpect(redirectedUrl("/oauth2/login?error"));
        mvc.perform(signIn(a[0], "not-the-password-0000", null, "10.10.0.9"))
                .andExpect(redirectedUrl("/oauth2/login?error"));
    }
}
