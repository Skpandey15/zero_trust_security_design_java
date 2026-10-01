package com.example.zerotrust.bff;

import com.example.zerotrust.bff.config.BffProperties;
import com.example.zerotrust.bff.web.AuthServerClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Import;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ADR-SEC-007: the BFF is the browser trust boundary. These pin the behaviour
 * the SPA depends on and the boundary it must not cross.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(BrowserBoundaryTest.StubAuthServer.class)
class BrowserBoundaryTest {

    /**
     * A hand-written stub rather than a Mockito mock: Mockito's inline agent
     * cannot self-attach on the JDK 27 this project targets, and a stub with an
     * observable call list says what it verifies just as plainly.
     */
    static class RecordingAuthServerClient extends AuthServerClient {
        final java.util.List<Object> calls = new java.util.concurrent.CopyOnWriteArrayList<>();
        ResponseEntity<Map<String, Object>> reply =
                ResponseEntity.status(HttpStatus.CREATED).body(Map.of("email", "a@example.com"));

        RecordingAuthServerClient() {
            super(new BffProperties(null, null, null, null));
        }

        @Override
        public ResponseEntity<Map<String, Object>> register(RegisterPayload payload) {
            calls.add(payload);
            return reply;
        }
    }

    @TestConfiguration
    static class StubAuthServer {
        @Bean @Primary RecordingAuthServerClient recordingAuthServerClient() {
            return new RecordingAuthServerClient();
        }
    }


    private static final String VALID = """
            {"email":"a@example.com","password":"a-long-enough-password","displayName":"Ada"}""";

    @Autowired MockMvc mvc;

    /** The SPA's handshake: read the cookie the BFF issued, echo it in a header. */
    private jakarta.servlet.http.Cookie csrfCookie() throws Exception {
        return mvc.perform(get("/api/session")).andReturn().getResponse().getCookie("XSRF-TOKEN");
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder withCsrf(
            org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request) throws Exception {
        jakarta.servlet.http.Cookie cookie = csrfCookie();
        return request.cookie(cookie).header("X-XSRF-TOKEN", cookie.getValue());
    }
    @Autowired RecordingAuthServerClient authServer;

    @Test
    void sessionEndpointIsPublicAndIssuesTheCsrfCookie() throws Exception {
        mvc.perform(get("/api/session"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(false))
                // Without this cookie the SPA's first POST would be rejected.
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andExpect(cookie().httpOnly("XSRF-TOKEN", false));
    }

    @Test
    void registrationWithoutCsrfTokenIsRejectedAndNeverReachesTheAuthServer() throws Exception {
        authServer.calls.clear();
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(VALID))
                .andExpect(status().isForbidden());

        assertThat(authServer.calls).isEmpty();
    }

    @Test
    void registrationWithCsrfIsRelayedAndTheAuthServerStatusIsPreserved() throws Exception {
        authServer.calls.clear();

        mvc.perform(withCsrf(post("/api/auth/register"))
                        .contentType(MediaType.APPLICATION_JSON).content(VALID))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("a@example.com"));

        assertThat(authServer.calls).hasSize(1);
    }

    @Test
    void registrationRejectsAShortPasswordWithoutCallingTheAuthServer() throws Exception {
        authServer.calls.clear();
        mvc.perform(withCsrf(post("/api/auth/register")).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"a@example.com","password":"short","displayName":"Ada"}"""))
                .andExpect(status().isBadRequest());

        assertThat(authServer.calls).isEmpty();
    }

    @Test
    void protectedApiAnswersWithAStatusCodeNotARedirectToALoginPage() throws Exception {
        mvc.perform(get("/api/anything-else"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void authorizationRequestCarriesAPkceChallenge() throws Exception {
        mvc.perform(get("/oauth2/authorization/zero-trust-web"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("code_challenge_method=S256")))
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("code_challenge=")));
    }
}
