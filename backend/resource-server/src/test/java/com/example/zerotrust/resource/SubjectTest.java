package com.example.zerotrust.resource;

import com.example.zerotrust.resource.authz.Subject;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** What the Resource Server makes of the claims the Authorization Server really sends. */
class SubjectTest {

    private static Jwt jwt(Map<String, Object> claims) {
        java.util.Map<String, Object> all = new java.util.HashMap<>(Map.of("sub", "u", "uid", 7L));
        all.putAll(claims);
        return new Jwt("t", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "RS256"), all);
    }

    @Test
    void scopeAsAnArrayIsReadTheWayAuthorizationServerEmitsIt() {
        // This is the form Spring Authorization Server sends. Parsing only the string form
        // denied every legitimate call.
        Subject s = Subject.from(jwt(Map.of("scope", List.of("documents.read", "documents.write"))));

        assertThat(s.scopes()).containsExactlyInAnyOrder("documents.read", "documents.write");
        assertThat(s.hasScope("documents.write")).isTrue();
    }

    @Test
    void scopeAsASpaceDelimitedStringIsReadToo() {
        // RFC 9068 / RFC 6749.
        Subject s = Subject.from(jwt(Map.of("scope", "documents.read  documents.approve")));

        assertThat(s.scopes()).containsExactlyInAnyOrder("documents.read", "documents.approve");
    }

    @Test
    void anyWhitespaceSeparatesScopesNotJustSpaces() {
        // In a Java string literal a lone backslash-s is a SPACE; the regex needs the escaped form.
        // Tabs and newlines are legal separators, and a scope glued to its neighbour matches nothing.
        Subject s = Subject.from(jwt(Map.of("scope", "documents.read\tdocuments.write\ndocuments.approve")));

        assertThat(s.scopes()).containsExactlyInAnyOrder("documents.read", "documents.write", "documents.approve");
    }

    @Test
    void aSingleElementArrayIsNotMistakenForAString() {
        assertThat(Subject.from(jwt(Map.of("scope", List.of("documents.read")))).scopes())
                .containsExactly("documents.read");
    }

    @Test
    void noScopeClaimMeansNoScopes() {
        assertThat(Subject.from(jwt(Map.of())).scopes()).isEmpty();
    }

    @Test
    void aScopeThatMerelyContainsAnotherDoesNotCount() {
        // Exact match: "documents.read.all" is not "documents.read".
        Subject s = Subject.from(jwt(Map.of("scope", List.of("documents.read.all"))));

        assertThat(s.hasScope("documents.read")).isFalse();
    }

    @Test
    void secondFactorIsProvedOnlyByTheOtpValue() {
        assertThat(Subject.from(jwt(Map.of("amr", List.of("pwd", "otp")))).provedSecondFactor()).isTrue();
        assertThat(Subject.from(jwt(Map.of("amr", List.of("pwd")))).provedSecondFactor()).isFalse();
        assertThat(Subject.from(jwt(Map.of())).provedSecondFactor()).isFalse();
    }

    @Test
    void aTokenWithNoUidCannotBecomeASubject() {
        Jwt noUid = new Jwt("t", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "RS256"), Map.of("sub", "u"));

        assertThatThrownBy(() -> Subject.from(noUid)).isInstanceOf(IllegalArgumentException.class);
    }
}
