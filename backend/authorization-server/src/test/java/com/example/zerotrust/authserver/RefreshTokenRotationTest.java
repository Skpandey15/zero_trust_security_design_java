package com.example.zerotrust.authserver;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Attack-path test: refresh-token rotation and family-wide revocation on reuse.
 * The refresh token lives in an httpOnly cookie (not the body), so the test reads
 * it from Set-Cookie and replays it as a request cookie.
 */
@SpringBootTest
@AutoConfigureMockMvc
class RefreshTokenRotationTest {

    @Autowired MockMvc mockMvc;

    static final String EMAIL = "rotation-test@example.com";
    static final String PASSWORD = "rotation-password-123";
    static final String IP = "10.0.0.11";

    @Test
    void reusedRefreshTokenKillsWholeFamily() throws Exception {
        register();
        String tokenA = loginAndGetRefreshCookie();

        // legitimate rotation: A -> B
        String tokenB = refresh(tokenA).andReturnCookie();

        // ATTACK: replaying already-rotated token A must fail...
        refresh(tokenA).expectUnauthorized();

        // ...and must also have revoked B (same family) — forcing re-login
        refresh(tokenB).expectUnauthorized();
    }

    private void register() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s","displayName":"Rot"}
                        """.formatted(EMAIL, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private String loginAndGetRefreshCookie() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .header("X-Forwarded-For", IP)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s"}
                        """.formatted(EMAIL, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn();
        Cookie c = result.getResponse().getCookie("refresh_token");
        org.junit.jupiter.api.Assertions.assertNotNull(c, "login must set the refresh_token cookie");
        return c.getValue();
    }

    private RefreshCall refresh(String token) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                .cookie(new Cookie("refresh_token", token)))
                .andReturn();
        return new RefreshCall(result);
    }

    private static class RefreshCall {
        private final MvcResult result;
        RefreshCall(MvcResult result) { this.result = result; }

        String andReturnCookie() {
            org.junit.jupiter.api.Assertions.assertEquals(200, result.getResponse().getStatus());
            Cookie c = result.getResponse().getCookie("refresh_token");
            org.junit.jupiter.api.Assertions.assertNotNull(c, "rotation must set a new refresh_token cookie");
            return c.getValue();
        }

        void expectUnauthorized() {
            org.junit.jupiter.api.Assertions.assertEquals(401, result.getResponse().getStatus());
        }
    }
}
