package com.example.zerotrust.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Attack-path test: brute-force lockout — after 5 failures within the window
 * the account is locked even for the CORRECT password.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccountLockoutTest {

    @Autowired MockMvc mockMvc;

    static final String EMAIL = "lockout-test@example.com";
    static final String PASSWORD = "lockout-password-123";
    static final String IP = "10.0.0.12";

    @Test
    void fiveFailuresLockTheAccount() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s","displayName":"Lock"}
                        """.formatted(EMAIL, PASSWORD)))
                .andExpect(status().isCreated());

        for (int i = 0; i < 5; i++) {
            attemptLogin("wrong-password-attempt-" + i).andExpect(status().isUnauthorized());
        }

        // 6th attempt with the CORRECT password must now be rate-limited
        attemptLogin(PASSWORD)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("RATE_LIMITED"));
    }

    private org.springframework.test.web.servlet.ResultActions attemptLogin(String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .header("X-Forwarded-For", IP)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s"}
                        """.formatted(EMAIL, password)));
    }
}
