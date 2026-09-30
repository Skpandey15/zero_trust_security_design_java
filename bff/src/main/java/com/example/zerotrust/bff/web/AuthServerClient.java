package com.example.zerotrust.bff.web;

import com.example.zerotrust.bff.config.BffProperties;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.Map;

/**
 * The BFF's calls to the Authorization Server on behalf of a browser that has
 * no session yet. Cluster-internal address, bounded timeouts, and only the
 * operations the UI genuinely needs.
 */
@Component
public class AuthServerClient {

    private static final ParameterizedTypeReference<Map<String, Object>> JSON_OBJECT =
            new ParameterizedTypeReference<>() {};

    private final RestClient client;

    public AuthServerClient(BffProperties props) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(10));
        this.client = RestClient.builder()
                .baseUrl(props.authServerBaseUrl())
                .requestFactory(factory)
                .build();
    }

    /** Returns the Authorization Server's status and JSON body unchanged, including 4xx. */
    public ResponseEntity<Map<String, Object>> register(RegisterPayload payload) {
        return client.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .body(payload)
                .exchange((request, response) ->
                        ResponseEntity.status(response.getStatusCode()).body(response.bodyTo(JSON_OBJECT)));
    }

    public record RegisterPayload(String email, String password, String displayName) {}
}
