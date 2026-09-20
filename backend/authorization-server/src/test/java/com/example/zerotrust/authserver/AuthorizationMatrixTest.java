package com.example.zerotrust.authserver;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Authorization matrix: anonymous vs regular USER against protected and
 * unlisted endpoints. Verifies least privilege AND deny-by-default.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationMatrixTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    static final String EMAIL = "matrix-test@example.com";
    static final String PASSWORD = "matrix-password-12";
    static final String IP = "10.0.0.14";

    String userToken;

    @BeforeEach
    void setup() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s","displayName":"Matrix"}
                        """.formatted(EMAIL, PASSWORD)));
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                .header("X-Forwarded-For", IP)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s"}
                        """.formatted(EMAIL, PASSWORD)))
                .andReturn();
        userToken = objectMapper.readTree(login.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    @Test
    void anonymousIsRejectedFromProtectedEndpoints() throws Exception {
        mockMvc.perform(get("/api/users/me")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/admin/security/insights").param("email", EMAIL))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void regularUserCanReadOwnProfileButNothingAdmin() throws Exception {
        mockMvc.perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        // least privilege: USER lacks users:read / users:manage / security:insights
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/admin/security/insights").param("email", EMAIL)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void unlistedEndpointsAreDeniedByDefault() throws Exception {
        // never registered in the filter chain -> denyAll, even with a valid token
        mockMvc.perform(get("/api/does-not-exist")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/does-not-exist"))
                .andExpect(status().isUnauthorized());
    }
}
