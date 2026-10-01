package com.example.zerotrust.authserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** The amr claim reports what the session proved, in RFC 8176 terms - and nothing it did not. */
class AssuranceClaimsTest {

    private static UsernamePasswordAuthenticationToken session(String... authorities) {
        return UsernamePasswordAuthenticationToken.authenticated("u", null,
                java.util.Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList());
    }

    @Test
    void passwordOnlyIsReportedAsPwd() {
        assertThat(AssuranceClaims.amrFor(session("ROLE_USER", "FACTOR_PASSWORD"))).containsExactly("pwd");
    }

    @Test
    void passwordPlusCodeIsReportedAsPwdAndOtp() {
        assertThat(AssuranceClaims.amrFor(session("ROLE_USER", "FACTOR_PASSWORD", "FACTOR_TOTP")))
                .containsExactlyInAnyOrder("pwd", "otp");
    }

    @Test
    void aSessionThatProvedNoFactorReportsNone() {
        // e.g. a client_credentials principal: there is no interactive factor to claim.
        assertThat(AssuranceClaims.amrFor(session("SCOPE_api.read"))).isEmpty();
        assertThat(AssuranceClaims.amrFor(null)).isEqualTo(List.of());
    }

    @Test
    void aRoleCannotImpersonateAFactor() {
        // Only the exact factor authorities count; a look-alike role grants nothing.
        assertThat(AssuranceClaims.amrFor(session("ROLE_FACTOR_TOTP", "factor_totp"))).isEmpty();
    }
}
