package com.example.zerotrust.bff.web;

import com.example.zerotrust.bff.config.BffProperties;
import com.example.zerotrust.bff.web.TokenExchangeClient.ExchangeFailed;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The only way the browser reaches the documents API and the tenants it can act in (ADR-SEC-007).
 *
 * <p>The browser sends a session cookie and a CSRF header. This controller turns
 * that into what the API actually accepts: a short-lived, single-audience,
 * down-scoped token obtained by exchange (ADR-SEC-016). The login token and the
 * cookie are never forwarded, and nothing the browser sent in {@code Authorization}
 * is trusted or relayed.
 *
 * <p>Deny by default: only the routes in the table below exist. A path that is
 * not listed is a 404 and triggers neither an exchange nor an upstream call - so
 * the BFF cannot be used as an open relay to whatever the Resource Server
 * happens to expose, and the path segments are constrained so a crafted id
 * cannot escape the API's path (no traversal, no SSRF).
 */
@RestController
public class ApiProxyController {

    private static final Logger log = LoggerFactory.getLogger(ApiProxyController.class);

    /** One permitted call, and the SINGLE scope a token for it carries. */
    private record Route(HttpMethod method, Pattern path, String scope) {
        boolean matches(HttpMethod m, String p) { return method.equals(m) && path.matcher(p).matches(); }
    }

    private static final String ID = "[A-Za-z0-9-]{1,64}";
    private static final List<Route> ROUTES = List.of(
            new Route(HttpMethod.GET,  Pattern.compile("/api/tenants"), "documents.read"),
            new Route(HttpMethod.GET,  Pattern.compile("/api/documents"), "documents.read"),
            new Route(HttpMethod.GET,  Pattern.compile("/api/documents/" + ID), "documents.read"),
            new Route(HttpMethod.POST, Pattern.compile("/api/documents"), "documents.write"),
            new Route(HttpMethod.POST, Pattern.compile("/api/documents/" + ID + "/submit"), "documents.write"),
            new Route(HttpMethod.POST, Pattern.compile("/api/documents/" + ID + "/approve"), "documents.approve"));

    private final TokenExchangeClient exchange;
    private final RestClient api;

    public ApiProxyController(BffProperties props, TokenExchangeClient exchange) {
        this.exchange = exchange;
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(15));
        this.api = RestClient.builder().baseUrl(props.apiBaseUrl()).requestFactory(factory).build();
    }

    @RequestMapping("/api/documents/**")
    public ResponseEntity<byte[]> documents(HttpServletRequest request,
                                            @RegisteredOAuth2AuthorizedClient("zero-trust-web") OAuth2AuthorizedClient login,
                                            @RequestBody(required = false) byte[] body) {
        return forward(request, login, body);
    }

    /** {@code /api/documents} itself is not matched by the {@code /**} mapping above. */
    @RequestMapping({"/api/documents", "/api/tenants"})
    public ResponseEntity<byte[]> documentsRoot(HttpServletRequest request,
                                                @RegisteredOAuth2AuthorizedClient("zero-trust-web") OAuth2AuthorizedClient login,
                                                @RequestBody(required = false) byte[] body) {
        return forward(request, login, body);
    }

    private ResponseEntity<byte[]> forward(HttpServletRequest request, OAuth2AuthorizedClient login, byte[] body) {
        HttpMethod method = HttpMethod.valueOf(request.getMethod());
        String path = request.getRequestURI().substring(request.getContextPath().length());

        Route route = ROUTES.stream().filter(r -> r.matches(method, path)).findFirst().orElse(null);
        if (route == null) {
            return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "No such resource.");
        }

        String token;
        try {
            token = exchange.exchange(login.getClientRegistration(), login.getAccessToken().getTokenValue(), route.scope());
        } catch (ExchangeFailed e) {
            // No fallback: the broad login token is NEVER sent in its place.
            log.warn("event=token_exchange_failed scope={} reason={}", route.scope(), e.getMessage());
            return error(HttpStatus.BAD_GATEWAY, "UPSTREAM_UNAVAILABLE", "The service is temporarily unavailable.");
        }

        String requestId = request.getHeader("X-Request-Id");
        String correlation = requestId != null && requestId.matches("[A-Za-z0-9._-]{8,64}") ? requestId : UUID.randomUUID().toString();

        URI uri = URI.create(path + (request.getQueryString() == null ? "" : "?" + request.getQueryString()));
        try {
            return api.method(method).uri(uri.toString())
                    .headers(h -> {
                        h.setBearerAuth(token);
                        h.set("X-Request-Id", correlation);
                        // Only what the API needs: never the browser's Cookie or Authorization.
                        String contentType = request.getContentType();
                        if (contentType != null) h.set(HttpHeaders.CONTENT_TYPE, contentType);
                        h.setAccept(List.of(MediaType.APPLICATION_JSON));
                    })
                    .body(body == null ? new byte[0] : body)
                    .exchange((req, res) -> {
                        ResponseEntity.BodyBuilder out = ResponseEntity.status(res.getStatusCode())
                                .header("X-Request-Id", correlation);
                        MediaType type = res.getHeaders().getContentType();
                        if (type != null) out.contentType(type);
                        // RFC 9470: a step-up demand must reach the client intact.
                        String challenge = res.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
                        if (challenge != null) out.header(HttpHeaders.WWW_AUTHENTICATE, challenge);
                        return out.body(res.getBody().readAllBytes());
                    });
        } catch (RuntimeException e) {
            log.warn("event=api_call_failed path={} reason={}", path, e.getClass().getSimpleName());
            return error(HttpStatus.BAD_GATEWAY, "UPSTREAM_UNAVAILABLE", "The service is temporarily unavailable.");
        }
    }

    private static ResponseEntity<byte[]> error(HttpStatus status, String code, String message) {
        String json = "{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}";
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Exposed for the tests: the scope a route's token carries, or null if the route does not exist. */
    static String scopeFor(HttpMethod method, String path) {
        return ROUTES.stream().filter(r -> r.matches(method, path)).map(Route::scope).findFirst().orElse(null);
    }
}
