package com.example.zerotrust.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * The context loads and Flyway applies the baseline schema.
 *
 * <p>A skeleton that compiles but cannot start is not a skeleton. This is the
 * gate that keeps it startable as configuration accumulates.
 */
@SpringBootTest
class ApplicationContextTest {

    @Test
    void contextLoads() {
        // Fails if any bean cannot be created or a migration is invalid.
    }
}
