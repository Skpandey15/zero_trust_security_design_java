package com.example.zerotrust.resource;

import com.example.zerotrust.resource.authz.Decision;
import com.example.zerotrust.resource.authz.JdbcMembershipRepository;
import com.example.zerotrust.resource.authz.LocalPolicyDecisionPoint;
import com.example.zerotrust.resource.authz.MembershipRepository;
import com.example.zerotrust.resource.authz.PolicyDecisionPoint;
import com.example.zerotrust.resource.authz.Subject;
import com.example.zerotrust.resource.authz.Action;
import com.example.zerotrust.resource.authz.TenantRole;
import com.example.zerotrust.resource.config.ResourceServerSecurityConfig;
import com.example.zerotrust.resource.documents.Document;
import com.example.zerotrust.resource.documents.DocumentRepository;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Shared wiring for the Resource Server tests.
 *
 * <ul>
 *   <li>The JWT decoder is built from a test key but with the PRODUCTION validator
 *       chain ({@link ResourceServerSecurityConfig#accessTokenValidator}), so the
 *       tests exercise the real rules rather than a copy of them.</li>
 *   <li>Membership and the policy point are wrapped so a test can make either one
 *       fail, to prove the service fails closed.</li>
 * </ul>
 */
@SpringBootTest(properties = {
        "app.token.jwk-set-uri=http://localhost:9000/oauth2/jwks",
        "app.token.issuer=" + TestTokens.ISSUER,
        "app.token.api-audience=" + TestTokens.AUDIENCE,
        "app.token.client-id=" + TestTokens.CLIENT_ID
})
@AutoConfigureMockMvc
@Import(ResourceServerTestSupport.Wiring.class)
abstract class ResourceServerTestSupport {

    static final String TENANT_A = "tenant-a";
    static final String TENANT_B = "tenant-b";

    @Autowired protected MockMvc mvc;
    @Autowired protected JdbcTemplate jdbc;
    @Autowired protected DocumentRepository documents;
    @Autowired protected Wiring.FailureSwitches failures;

    @BeforeEach
    void cleanSlate() {
        // The identity database owns this table in real deployments; tests stand one up.
        jdbc.execute("CREATE TABLE IF NOT EXISTS public.subject_tenant_membership ("
                + "user_id BIGINT NOT NULL, tenant_id VARCHAR(36) NOT NULL, role VARCHAR(64) NOT NULL, "
                + "PRIMARY KEY (user_id, tenant_id))");
        jdbc.execute("DELETE FROM public.subject_tenant_membership");
        jdbc.execute("CREATE TABLE IF NOT EXISTS public.tenants (id VARCHAR(36) PRIMARY KEY, name VARCHAR(160) NOT NULL, status VARCHAR(16) NOT NULL)");
        jdbc.execute("DELETE FROM public.tenants");
        documents.deleteAll();
        failures.membershipDown.set(false);
        failures.policyDown.set(false);
    }

    protected void member(long uid, String tenant, String role) {
        Integer known = jdbc.queryForObject("SELECT COUNT(*) FROM public.tenants WHERE id = ?", Integer.class, tenant);
        if (known == null || known == 0) {
            jdbc.update("INSERT INTO public.tenants (id, name, status) VALUES (?, ?, 'ACTIVE')", tenant, "Workspace " + tenant);
        }
        jdbc.update("INSERT INTO public.subject_tenant_membership (user_id, tenant_id, role) VALUES (?, ?, ?)",
                uid, tenant, role);
    }

    protected Document draft(String tenant, long author, String title) {
        return documents.save(Document.draft(tenant, title, "body of " + title, author));
    }

    protected Document submitted(String tenant, long author, String title) {
        Document d = Document.draft(tenant, title, "body of " + title, author);
        d.submit(author);
        return documents.save(d);
    }

    protected static String bearer(String token) {
        return "Bearer " + token;
    }

    @TestConfiguration
    static class Wiring {

        /** Flags a test flips to simulate a dependency being down. */
        static class FailureSwitches {
            final AtomicBoolean membershipDown = new AtomicBoolean();
            final AtomicBoolean policyDown = new AtomicBoolean();
        }

        @Bean
        FailureSwitches failureSwitches() {
            return new FailureSwitches();
        }

        @Bean
        @Primary
        JwtDecoder testJwtDecoder() throws Exception {
            RSAKey key = TestTokens.KEY;
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).validateType(false).build();
            decoder.setJwtValidator(ResourceServerSecurityConfig.accessTokenValidator(
                    TestTokens.ISSUER, TestTokens.AUDIENCE, TestTokens.CLIENT_ID));
            return decoder;
        }

        @Bean
        @Primary
        MembershipRepository flakyMembership(JdbcMembershipRepository real, FailureSwitches switches) {
            return new MembershipRepository() {
                @Override
                public Optional<TenantRole> roleOf(long uid, String tenantId) {
                    if (switches.membershipDown.get()) throw new IllegalStateException("membership store down");
                    return real.roleOf(uid, tenantId);
                }

                @Override
                public Map<String, TenantRole> tenantsOf(long uid) {
                    if (switches.membershipDown.get()) throw new IllegalStateException("membership store down");
                    return real.tenantsOf(uid);
                }

                @Override
                public List<TenantInfo> describe(long uid) {
                    if (switches.membershipDown.get()) throw new IllegalStateException("membership store down");
                    return real.describe(uid);
                }
            };
        }

        @Bean
        @Primary
        PolicyDecisionPoint flakyPolicy(LocalPolicyDecisionPoint real, FailureSwitches switches) {
            return new PolicyDecisionPoint() {
                @Override
                public Decision decide(Subject subject, Action action, TenantRole role) {
                    if (switches.policyDown.get()) throw new IllegalStateException("policy point down");
                    return real.decide(subject, action, role);
                }
            };
        }
    }
}
