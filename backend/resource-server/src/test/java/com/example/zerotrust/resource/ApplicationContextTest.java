package com.example.zerotrust.resource;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * The context loads with the strict at+jwt decoder wired.
 *
 * <p>This also proves an ADR-SEC-008 property worth having in CI: the
 * {@code createAtJwtValidator()} builder refuses to construct without an
 * audience, so forgetting to pin one is a startup failure rather than a silent
 * hole. Remove {@code .audience(...)} from the decoder and this test fails with
 * {@code IllegalArgumentException: aud must be validated}.
 */
@SpringBootTest(properties = {
        "app.token.jwk-set-uri=http://localhost:9000/oauth2/jwks",
        "app.token.issuer=http://localhost:9000",
        "app.token.api-audience=zero-trust-api",
        "app.token.client-id=zero-trust-web"
})
class ApplicationContextTest {

    @Test
    void contextLoads() {
    }
}
