package com.example.zerotrust.bff.web;

import com.example.zerotrust.bff.config.BffProperties;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.Map;

/**
 * RFC 8693 token exchange (ADR-SEC-016). The BFF holds one broad login token and
 * never lets it leave. For each API call it trades that token for a NEW one
 * aimed at a single API and narrowed to the scope that one call needs.
 *
 * <p>There is no fallback. If the exchange fails the call fails: sending the
 * broad login token "just this once" would defeat the whole point, and a
 * failure here is exactly when it would be most tempting.
 */
@Component
public class TokenExchangeClient {

    /** The exchange could not be completed. The caller must not substitute a broader token. */
    public static class ExchangeFailed extends RuntimeException {
        public ExchangeFailed(String message, Throwable cause) { super(message, cause); }
    }

    private static final ParameterizedTypeReference<Map<String, Object>> JSON_OBJECT = new ParameterizedTypeReference<>() {};
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final RestClient client;
    private final String audience;

    public TokenExchangeClient(BffProperties props) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(10));
        // The Authorization Server's cluster-internal address: this call never leaves the cluster.
        this.client = RestClient.builder().baseUrl(props.authServerBaseUrl()).requestFactory(factory).build();
        this.audience = props.apiAudience();
    }

    /** A token for {@code scope} only, addressed to the API audience. */
    public String exchange(ClientRegistration registration, String subjectToken, String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        form.add("subject_token", subjectToken);
        form.add("subject_token_type", ACCESS_TOKEN_TYPE);
        form.add("audience", audience);
        form.add("scope", scope);

        try {
            Map<String, Object> response = client.post()
                    .uri("/oauth2/token")
                    .headers(h -> h.setBasicAuth(registration.getClientId(), registration.getClientSecret()))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(JSON_OBJECT);
            Object token = response == null ? null : response.get("access_token");
            if (!(token instanceof String t) || t.isBlank()) {
                throw new ExchangeFailed("token exchange returned no access token", null);
            }
            return t;
        } catch (ExchangeFailed e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ExchangeFailed("token exchange failed", e);
        }
    }
}
