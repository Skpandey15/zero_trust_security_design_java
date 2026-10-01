package com.example.zerotrust.resource;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.zerotrust.resource.documents.Document;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ADR-SEC-024: when a decision cannot be made, nothing is permitted - an
 * unavailable dependency is never an implicit allow. ADR-SEC-023: every decision
 * is recorded with the policy that produced it and a correlation id.
 */
class FailClosedAndAuditTest extends ResourceServerTestSupport {

    private ListAppender<ILoggingEvent> decisions;
    private Logger logger;

    @BeforeEach
    void captureDecisionLog() {
        logger = (Logger) LoggerFactory.getLogger("security.decisions");
        decisions = new ListAppender<>();
        decisions.start();
        logger.addAppender(decisions);
    }

    @AfterEach
    void releaseDecisionLog() {
        logger.detachAppender(decisions);
    }

    private String token(long uid) {
        return bearer(TestTokens.token().uid(uid).withSecondFactor().build());
    }

    private String logged() {
        return decisions.list.stream().map(ILoggingEvent::getFormattedMessage).reduce("", (a, b) -> a + "\n" + b);
    }

    // ---- fail closed ----

    @Test
    void deniesAPrivilegedWriteWhenThePolicyPointIsDown() throws Exception {
        // deniesPolicyDecisionOnPrivilegedWriteWhenPdpUnavailable
        member(1, TENANT_A, "MEMBER");
        member(2, TENANT_A, "APPROVER");
        Document doc = submitted(TENANT_A, 1, "x");
        failures.policyDown.set(true);

        mvc.perform(post("/api/documents/" + doc.getId() + "/approve").header("Authorization", token(2)))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("AUTHORIZATION_UNAVAILABLE"));

        assertThat(documents.findById(doc.getId()).orElseThrow().getStatus())
                .as("an outage must not approve anything").isEqualTo(Document.Status.SUBMITTED);
        assertThat(logged()).contains("decision=DENY").contains("policy decision point unavailable");
    }

    @Test
    void deniesAWriteWhenMembershipCannotBeChecked() throws Exception {
        member(1, TENANT_A, "OWNER");
        failures.membershipDown.set(true);
        long before = documents.count();

        mvc.perform(post("/api/documents").header("Authorization", token(1)).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenantId\":\"" + TENANT_A + "\",\"title\":\"x\",\"body\":\"x\"}"))
                .andExpect(status().isServiceUnavailable());

        assertThat(documents.count()).isEqualTo(before);
    }

    @Test
    void deniesAReadWhenMembershipCannotBeChecked() throws Exception {
        member(1, TENANT_A, "OWNER");
        Document doc = draft(TENANT_A, 1, "x");
        failures.membershipDown.set(true);

        mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", token(1)))
                .andExpect(status().isServiceUnavailable());
        mvc.perform(get("/api/documents").header("Authorization", token(1)))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    void recoversWhenTheDependencyReturns() throws Exception {
        member(1, TENANT_A, "OWNER");
        Document doc = draft(TENANT_A, 1, "x");
        failures.membershipDown.set(true);
        mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", token(1)))
                .andExpect(status().isServiceUnavailable());

        failures.membershipDown.set(false);

        mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", token(1)))
                .andExpect(status().isOk());
    }

    // ---- audit ----

    @Test
    void recordsAnAllowWithItsPolicyVersionAndCorrelationId() throws Exception {
        // recordsCorrelatedSecurityDecisionEvent
        member(1, TENANT_A, "MEMBER");
        Document doc = draft(TENANT_A, 1, "x");

        mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", token(1))
                        .header("X-Request-Id", "req-12345678"))
                .andExpect(status().isOk());

        assertThat(logged())
                .contains("requestId=req-12345678")
                .contains("subject=1")
                .contains("action=DOCUMENT_READ")
                .contains("tenant=" + TENANT_A)
                .contains("resource=" + doc.getId())
                .contains("decision=ALLOW")
                .contains("policy=documents@1");
    }

    @Test
    void recordsAStepUpAndADenyAsDistinctOutcomes() throws Exception {
        member(1, TENANT_A, "MEMBER");
        member(2, TENANT_A, "APPROVER");
        Document doc = submitted(TENANT_A, 1, "x");

        mvc.perform(post("/api/documents/" + doc.getId() + "/approve")
                .header("Authorization", bearer(TestTokens.token().uid(2).amr("pwd").build())));
        mvc.perform(post("/api/documents/" + doc.getId() + "/approve")
                .header("Authorization", bearer(TestTokens.token().uid(1).withSecondFactor().build())));

        assertThat(logged()).contains("decision=STEP_UP").contains("decision=DENY");
    }

    @Test
    void recordsACrossTenantAttemptWithTheReason() throws Exception {
        member(1, TENANT_A, "OWNER");
        Document theirs = draft(TENANT_B, 2, "secret");

        mvc.perform(get("/api/documents/" + theirs.getId()).header("Authorization", token(1)));

        // The caller learns nothing (404); the audit trail learns everything.
        assertThat(logged()).contains("decision=DENY").contains("no standing in tenant").contains("tenant=" + TENANT_B);
    }

    @Test
    void aGeneratedCorrelationIdIsReturnedWhenNoneIsSupplied() throws Exception {
        member(1, TENANT_A, "MEMBER");
        Document doc = draft(TENANT_A, 1, "x");

        String id = mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", token(1)))
                .andReturn().getResponse().getHeader("X-Request-Id");

        assertThat(id).isNotBlank();
        assertThat(logged()).contains("requestId=" + id);
    }

    @Test
    void aForgedCorrelationIdCannotInjectIntoTheAuditLog() throws Exception {
        // A newline in a caller-supplied id would let a client forge a log line.
        member(1, TENANT_A, "MEMBER");
        Document doc = draft(TENANT_A, 1, "x");

        mvc.perform(get("/api/documents/" + doc.getId()).header("Authorization", token(1))
                .header("X-Request-Id", "abc\nevent=authz_decision decision=ALLOW subject=999"));

        assertThat(logged()).doesNotContain("subject=999");
    }
}
