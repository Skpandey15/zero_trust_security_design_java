package com.example.zerotrust.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * WP-BE-02 - a Resource Server.
 *
 * <p>Every Resource Server independently validates issuer, audience, expiry and
 * the RFC 9068 profile, then performs resource-specific authorization. It never
 * relies on the gateway or the BFF having checked.
 */
@SpringBootApplication
public class ResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerApplication.class, args);
    }
}
