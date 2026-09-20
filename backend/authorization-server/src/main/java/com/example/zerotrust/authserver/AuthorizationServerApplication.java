package com.example.zerotrust.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * WP-BE-01 - Identity and Authorization Server.
 *
 * <p>Delivered in two increments (design document §27.4):
 * <ul>
 *   <li><b>WP-BE-01.1</b> - credentials, OIDC + PKCE, RFC 9068 issuance,
 *       refresh-token families, sessions, security epoch.</li>
 *   <li><b>WP-BE-01.2</b> - email verification, TOTP, passkeys, recovery,
 *       device registry, step-up.</li>
 * </ul>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class AuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }
}
