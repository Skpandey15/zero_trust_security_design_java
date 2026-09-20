package com.example.zerotrust.bff.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.bff")
public record BffProperties(
        /** Base URL of the Resource Server the BFF forwards to. */
        String apiBaseUrl,
        /** Content-Security-Policy. Tightened per environment; never widened for convenience. */
        String contentSecurityPolicy) {

    public BffProperties {
        if (apiBaseUrl == null || apiBaseUrl.isBlank()) apiBaseUrl = "http://localhost:9100";
        if (contentSecurityPolicy == null || contentSecurityPolicy.isBlank()) {
            contentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; object-src 'none'";
        }
    }
}
