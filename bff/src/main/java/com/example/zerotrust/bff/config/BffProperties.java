package com.example.zerotrust.bff.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.bff")
public record BffProperties(
        /** Base URL of the Resource Server the BFF forwards to. */
        String apiBaseUrl,
        /**
         * Cluster-internal base URL of the Authorization Server, for the calls
         * the BFF makes on the browser's behalf (registration). Deliberately
         * not the public issuer URL: this traffic never leaves the cluster.
         */
        String authServerBaseUrl,
        /** The audience of the API this BFF calls. A token exchanged for it is valid there and nowhere else. */
        String apiAudience,
        /** Content-Security-Policy. Tightened per environment; never widened for convenience. */
        String contentSecurityPolicy) {

    public BffProperties {
        if (apiBaseUrl == null || apiBaseUrl.isBlank()) apiBaseUrl = "http://localhost:9100";
        if (authServerBaseUrl == null || authServerBaseUrl.isBlank()) authServerBaseUrl = "http://localhost:9000";
        if (apiAudience == null || apiAudience.isBlank()) apiAudience = "zero-trust-api";
        if (contentSecurityPolicy == null || contentSecurityPolicy.isBlank()) {
            contentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; object-src 'none'";
        }
    }
}
