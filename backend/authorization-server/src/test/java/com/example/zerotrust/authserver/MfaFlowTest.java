package com.example.zerotrust.authserver;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.example.zerotrust.authserver.service.TotpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full MFA lifecycle: setup -> activate -> password-only login rejected ->
 * password+TOTP login accepted -> wrong code rejected.
 */
@SpringBootTest
@AutoConfigureMockMvc
class MfaFlowTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired TotpService totpService;

    static final String EMAIL = "mfa-test@example.com";
    static final String PASSWORD = "mfa-password-1234";
    static final String IP = "10.0.0.13";

    @Test
    void mfaLifecycle() throws Exception {
        // register + first login (no MFA yet)
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s","displayName":"Mfa"}
                        """.formatted(EMAIL, PASSWORD)))
                .andExpect(status().isCreated());
        String accessToken = login(null).andReturnAccessToken();

        // setup: obtain the TOTP secret
        MvcResult setup = mockMvc.perform(post("/api/users/me/mfa/setup")
                .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.otpauthUri", org.hamcrest.Matchers.startsWith("otpauth://totp/")))
                .andReturn();
        String secret = objectMapper.readTree(setup.getResponse().getContentAsString())
                .get("secret").asText();

        // activate with a valid current code
        mockMvc.perform(post("/api/users/me/mfa/activate")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"code":"%s"}
                        """.formatted(currentCode(secret))))
                .andExpect(status().isNoContent());

        // password-only login must now demand the second factor
        login(null).expect(401, "MFA_REQUIRED");

        // wrong code rejected
        login("000000").expect(401, "UNAUTHORIZED");

        // correct code accepted
        login(currentCode(secret)).expectOk();
    }

    private String currentCode(String secret) {
        return totpService.generateCode(secret, totpService.currentTimeStep());
    }

    private LoginCall login(String otpCode) throws Exception {
        String body = otpCode == null
                ? """
                  {"email":"%s","password":"%s"}
                  """.formatted(EMAIL, PASSWORD)
                : """
                  {"email":"%s","password":"%s","otpCode":"%s"}
                  """.formatted(EMAIL, PASSWORD, otpCode);
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .header("X-Forwarded-For", IP)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andReturn();
        return new LoginCall(result);
    }

    private class LoginCall {
        private final MvcResult result;
        LoginCall(MvcResult result) { this.result = result; }

        String andReturnAccessToken() throws Exception {
            org.junit.jupiter.api.Assertions.assertEquals(200, result.getResponse().getStatus());
            JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
            return node.get("accessToken").asText();
        }

        void expectOk() {
            org.junit.jupiter.api.Assertions.assertEquals(200, result.getResponse().getStatus());
        }

        void expect(int statusCode, String code) throws Exception {
            org.junit.jupiter.api.Assertions.assertEquals(statusCode, result.getResponse().getStatus());
            JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
            org.junit.jupiter.api.Assertions.assertEquals(code, node.get("code").asText());
        }
    }
}
