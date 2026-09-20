package com.example.zerotrust.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Browser origins permitted to call the API cross-origin (CORS). Empty by
 * default — same-origin deployments (UI served by, or proxied through, the same
 * host) need no entries. Set app.cors.allowed-origins when the SPA is hosted on
 * a different origin than the backend.
 */
@ConfigurationProperties(prefix = "app.cors")
public record CorsProperties(List<String> allowedOrigins) {

    public CorsProperties {
        allowedOrigins = allowedOrigins == null
                ? List.of()
                : allowedOrigins.stream().filter(o -> o != null && !o.isBlank()).map(String::trim).toList();
    }
}
