package com.example.zerotrust.authserver;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression test for a permanent-lockout defect.
 *
 * Three failed logins pushed an account over the step-up risk threshold. Step-up is
 * only ever demanded of accounts with NO second factor, and enrolling a second factor
 * requires an access token — so the correct password returned 403 STEP_UP_REQUIRED
 * forever, with no path back in. The failure counter did not help: isHighRisk() read
 * the raw failedCount, which recordFailure() only rolls over on the NEXT failure, so
 * the count never decayed on its own.
 *
 * Fixes under test: the risk read is window-bounded, and STEP_UP_REQUIRED now carries
 * an enrolment-scoped token so the demand is satisfiable.
 */
@SpringBootTest(properties = "app.fitness=stepup")
@AutoConfigureMockMvc
class StepUpEscapeTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    static final String EMAIL = "stepup-escape@example.com";
    static final String PASSWORD = "stepup-password-123";

    @Test
    void riskyLoginHandsBackAnEnrolmentTokenInsteadOfADeadEnd() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s","displayName":"StepUp"}
                                """.formatted(EMAIL, PASSWORD)))
                .andExpect(status().isCreated());

        for (int i = 0; i < 3; i++) {
            login("wrong-password-" + i).andExpect(status().isUnauthorized());
        }

        // Correct password on a now-risky account: still refused for a full session...
        MvcResult stepUp = login(PASSWORD)
                .andExpect(status().isForbidden())
                .andReturn();
        JsonNode body = objectMapper.readTree(stepUp.getResponse().getContentAsString());
        assertEquals("STEP_UP_REQUIRED", body.get("code").asText());

        // ...but the response must carry a way to satisfy the demand it just made.
        String stepUpToken = body.get("stepUpToken").asText();
        assertNotNull(stepUpToken);

        // The enrolment token reaches MFA setup, so the user can actually get unstuck.
        mockMvc.perform(post("/api/users/me/mfa/setup")
                        .header("Authorization", "Bearer " + stepUpToken))
                .andExpect(status().isOk());

        // ...and grants nothing beyond that: no admin surface.
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + stepUpToken))
                .andExpect(status().isForbidden());
    }

    private org.springframework.test.web.servlet.ResultActions login(String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"%s"}
                        """.formatted(EMAIL, password)));
    }
}
