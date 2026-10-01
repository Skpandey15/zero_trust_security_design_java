package com.example.zerotrust.bff.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Client;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ADR-SEC-016 / ADR-SEC-007. The browser holds a cookie; the API wants a token
 * aimed at it. The BFF bridges the two by exchange, and these tests pin what
 * crosses that bridge - and, as important, what does not.
 *
 * <p>Stand-in servers play the Authorization Server and the Resource Server, so
 * each test can see exactly what the BFF sent them.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiProxyTest {

    private static final String LOGIN_TOKEN = "LOGIN-TOKEN-never-to-be-forwarded";

    /** What a stand-in server saw. */
    record Seen(String method, String path, Map<String, String> headers, String body) {}

    private static final List<Seen> authServerSaw = new CopyOnWriteArrayList<>();
    private static final List<Seen> apiSaw = new CopyOnWriteArrayList<>();
    private static final AtomicInteger authServerStatus = new AtomicInteger(200);
    private static final AtomicInteger apiStatus = new AtomicInteger(200);
    private static final AtomicReference<String> apiBody = new AtomicReference<>("[]");
    private static final AtomicReference<String> apiChallenge = new AtomicReference<>();

    private static final HttpServer AUTH_SERVER = start(exchange -> {
        authServerSaw.add(seen(exchange));
        int code = authServerStatus.get();
        String scope = formValue(authServerSaw.get(authServerSaw.size() - 1).body(), "scope");
        String json = code == 200
                ? "{\"access_token\":\"EXCHANGED-" + scope + "\",\"token_type\":\"Bearer\",\"expires_in\":300}"
                : "{\"error\":\"invalid_scope\"}";
        reply(exchange, code, json, null);
    });

    private static final HttpServer API = start(exchange -> {
        apiSaw.add(seen(exchange));
        reply(exchange, apiStatus.get(), apiBody.get(), apiChallenge.get());
    });

    @DynamicPropertySource
    static void upstreams(DynamicPropertyRegistry registry) {
        registry.add("app.bff.auth-server-base-url", () -> "http://localhost:" + AUTH_SERVER.getAddress().getPort());
        registry.add("app.bff.api-base-url", () -> "http://localhost:" + API.getAddress().getPort());
    }

    @AfterAll
    static void stop() {
        AUTH_SERVER.stop(0);
        API.stop(0);
    }

    @Autowired MockMvc mvc;

    @BeforeEach
    void reset() {
        authServerSaw.clear();
        apiSaw.clear();
        authServerStatus.set(200);
        apiStatus.set(200);
        apiBody.set("[]");
        apiChallenge.set(null);
    }

    /** A signed-in browser: a session whose login token the BFF holds server-side. */
    private static MockHttpServletRequestBuilder signedIn(MockHttpServletRequestBuilder request) {
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, LOGIN_TOKEN,
                Instant.now(), Instant.now().plusSeconds(300));
        return request.with(oauth2Login()).with(oauth2Client("zero-trust-web").accessToken(token));
    }

    private MockHttpServletRequestBuilder withCsrf(MockHttpServletRequestBuilder request) throws Exception {
        Cookie cookie = mvc.perform(get("/api/session")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        return request.cookie(cookie).header("X-XSRF-TOKEN", cookie.getValue());
    }

    // ---- what crosses the bridge ----

    @Test
    void aReadIsExchangedForAReadOnlyTokenAimedAtTheApi() throws Exception {
        mvc.perform(signedIn(get("/api/documents"))).andExpect(status().isOk());

        assertThat(authServerSaw).hasSize(1);
        String form = authServerSaw.get(0).body();
        assertThat(formValue(form, "grant_type")).isEqualTo("urn:ietf:params:oauth:grant-type:token-exchange");
        assertThat(formValue(form, "subject_token")).as("the login token is the subject being exchanged").isEqualTo(LOGIN_TOKEN);
        assertThat(formValue(form, "audience")).isEqualTo("zero-trust-api");
        assertThat(formValue(form, "scope")).as("down-scoped to exactly what this call needs").isEqualTo("documents.read");
        assertThat(authServerSaw.get(0).headers().get("authorization")).as("authenticated as the client").startsWith("Basic ");
    }

    @Test
    void theTenantListIsAReadOfTheSameKind() throws Exception {
        mvc.perform(signedIn(get("/api/tenants"))).andExpect(status().isOk());

        assertThat(formValue(authServerSaw.get(0).body(), "scope")).isEqualTo("documents.read");
        assertThat(apiSaw.get(0).path()).isEqualTo("/api/tenants");
    }

    @Test
    void theApiReceivesTheExchangedTokenAndNeverTheLoginToken() throws Exception {
        mvc.perform(signedIn(get("/api/documents"))).andExpect(status().isOk());

        assertThat(apiSaw).hasSize(1);
        assertThat(apiSaw.get(0).headers().get("authorization")).isEqualTo("Bearer EXCHANGED-documents.read");
        assertThat(apiSaw.get(0).headers().values()).noneMatch(v -> v.contains(LOGIN_TOKEN));
    }

    @Test
    void eachRouteGetsTheSingleScopeItNeeds() throws Exception {
        mvc.perform(signedIn(get("/api/documents/abc-123")));
        mvc.perform(signedIn(withCsrf(post("/api/documents")).contentType(MediaType.APPLICATION_JSON)
                .content("{\"tenantId\":\"t\",\"title\":\"x\",\"body\":\"y\"}")));
        mvc.perform(signedIn(withCsrf(post("/api/documents/abc-123/submit"))));
        mvc.perform(signedIn(withCsrf(post("/api/documents/abc-123/approve"))));

        List<String> scopes = authServerSaw.stream().map(s -> formValue(s.body(), "scope")).toList();
        assertThat(scopes).containsExactly("documents.read", "documents.write", "documents.write", "documents.approve");
    }

    @Test
    void theBrowsersCookieAndAuthorizationHeaderAreNotRelayed() throws Exception {
        mvc.perform(signedIn(get("/api/documents"))
                .cookie(new Cookie("ZTSESSION", "session-secret"))
                .header("Authorization", "Bearer something-the-browser-made-up"));

        Map<String, String> headers = apiSaw.get(0).headers();
        assertThat(headers.get("cookie")).isNull();
        assertThat(headers.get("authorization")).isEqualTo("Bearer EXCHANGED-documents.read");
        assertThat(headers.values()).noneMatch(v -> v.contains("session-secret") || v.contains("made-up"));
    }

    @Test
    void theApisAnswerPassesThroughUnchanged() throws Exception {
        apiBody.set("[{\"id\":\"d1\",\"title\":\"hello\"}]");

        mvc.perform(signedIn(get("/api/documents")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title").value("hello"));
    }

    @Test
    void aStepUpDemandReachesTheBrowserIntact() throws Exception {
        apiStatus.set(403);
        apiBody.set("{\"code\":\"STEP_UP_REQUIRED\",\"message\":\"needs a second factor\"}");
        apiChallenge.set("Bearer error=\"insufficient_user_authentication\"");

        mvc.perform(signedIn(withCsrf(post("/api/documents/abc-123/approve"))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("STEP_UP_REQUIRED"))
                .andExpect(header().string("WWW-Authenticate", "Bearer error=\"insufficient_user_authentication\""));
    }

    // ---- what must not cross ----

    @Test
    void aFailedExchangeFailsTheCallAndNeverFallsBackToTheLoginToken() throws Exception {
        authServerStatus.set(400);

        mvc.perform(signedIn(get("/api/documents")))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.code").value("UPSTREAM_UNAVAILABLE"));

        assertThat(apiSaw).as("the API was never called - and certainly not with the broad token").isEmpty();
    }

    @Test
    void anUnlistedPathIsNotRelayedAndTriggersNoExchange() throws Exception {
        mvc.perform(signedIn(get("/api/documents/abc/delete"))).andExpect(status().isNotFound());
        mvc.perform(signedIn(withCsrf(post("/api/documents/abc/purge")))).andExpect(status().isNotFound());

        assertThat(authServerSaw).isEmpty();
        assertThat(apiSaw).isEmpty();
    }

    @Test
    void aMethodThatIsNotListedForARouteIsNotRelayed() throws Exception {
        // DELETE /api/documents/{id} is not a route, even though GET on the same path is.
        mvc.perform(signedIn(withCsrf(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/api/documents/abc-123"))))
                .andExpect(status().isNotFound());
        assertThat(apiSaw).isEmpty();
    }

    @Test
    void aCraftedIdCannotEscapeTheApisPath() throws Exception {
        // No traversal, no smuggled path segments, no scheme tricks (SSRF).
        for (String evil : List.of("/api/documents/..%2F..%2Factuator%2Fenv", "/api/documents/a%2Fb",
                "/api/documents/http:%2F%2Fevil", "/api/documents/%2e%2e")) {
            mvc.perform(signedIn(get(evil)));
        }
        assertThat(apiSaw).isEmpty();
        assertThat(authServerSaw).isEmpty();
    }

    @Test
    void aSignedOutBrowserGetsA401AndNothingIsExchanged() throws Exception {
        mvc.perform(get("/api/documents")).andExpect(status().isUnauthorized());

        assertThat(authServerSaw).isEmpty();
        assertThat(apiSaw).isEmpty();
    }

    @Test
    void aStateChangingCallWithoutACsrfTokenIsRefusedBeforeAnythingHappens() throws Exception {
        mvc.perform(signedIn(post("/api/documents/abc-123/approve"))).andExpect(status().isForbidden());

        assertThat(authServerSaw).isEmpty();
        assertThat(apiSaw).isEmpty();
    }

    @Test
    void routeTableMatchesTheApisSurfaceExactly() {
        assertThat(ApiProxyController.scopeFor(HttpMethod.GET, "/api/documents")).isEqualTo("documents.read");
        assertThat(ApiProxyController.scopeFor(HttpMethod.POST, "/api/documents/x/approve")).isEqualTo("documents.approve");
        assertThat(ApiProxyController.scopeFor(HttpMethod.PUT, "/api/documents/x")).isNull();
        assertThat(ApiProxyController.scopeFor(HttpMethod.GET, "/actuator/env")).isNull();
    }

    // ---- stand-in plumbing ----

    private static HttpServer start(com.sun.net.httpserver.HttpHandler handler) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/", handler);
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Seen seen(HttpExchange exchange) throws IOException {
        Map<String, String> headers = new java.util.HashMap<>();
        exchange.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), String.join(",", v)));
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        return new Seen(exchange.getRequestMethod(), exchange.getRequestURI().getPath(), headers, body);
    }

    private static void reply(HttpExchange exchange, int status, String json, String challenge) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        if (challenge != null) exchange.getResponseHeaders().add("WWW-Authenticate", challenge);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static String formValue(String form, String name) {
        for (String pair : form.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv[0].equals(name) && kv.length == 2) {
                return java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
