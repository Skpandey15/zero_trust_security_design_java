package com.example.zerotrust.bff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * WP-UI-01 - Backend For Frontend.
 *
 * <p>ADR-SEC-007: this service owns every OAuth credential. The browser holds
 * only an opaque, HttpOnly session cookie and never receives an access or
 * refresh token, so an XSS defect in the front end yields a session an attacker
 * can abuse while the page is open - not a portable credential they can replay
 * from their own machine.
 */
@SpringBootApplication
public class BffApplication {

    public static void main(String[] args) {
        SpringApplication.run(BffApplication.class, args);
    }
}
