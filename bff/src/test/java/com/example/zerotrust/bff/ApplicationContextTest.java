package com.example.zerotrust.bff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * The context loads without reaching the network.
 *
 * <p>The runtime config uses {@code issuer-uri}, which performs OIDC discovery
 * at startup and therefore requires the Authorization Server to be running.
 * The test overrides it with explicit endpoints so this gate stays hermetic —
 * a context test that needs another service running is a test that gets
 * disabled.
 */
@SpringBootTest
@ActiveProfiles("test")
class ApplicationContextTest {

    @Test
    void contextLoads() {
    }
}
