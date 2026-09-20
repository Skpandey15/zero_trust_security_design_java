package com.example.zerotrust.authserver.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

/**
 * Security-focused Micrometer metrics, exposed via /actuator/prometheus.
 * Logs answer "what happened"; these answer "is it happening right now" —
 * the inputs for dashboards and alert rules (e.g. alert when
 * rate(auth_login_failure_total[5m]) spikes, page on any token-reuse event).
 */
@Component
public class SecurityMetrics {

    private final Counter loginSuccess;
    private final MeterRegistry registry;
    private final Counter lockouts;
    private final Counter ipThrottled;
    private final Counter tokenReuse;
    private final Counter mfaActivations;
    private final Timer aiInsightTimer;

    public SecurityMetrics(MeterRegistry registry) {
        this.registry = registry;
        this.loginSuccess = Counter.builder("auth_login_success_total")
                .description("Successful logins").register(registry);
        this.lockouts = Counter.builder("auth_account_lockout_total")
                .description("Account lockouts triggered by repeated failures").register(registry);
        this.ipThrottled = Counter.builder("auth_ip_throttled_total")
                .description("Requests rejected by the per-IP rate limit").register(registry);
        this.tokenReuse = Counter.builder("auth_refresh_token_reuse_total")
                .description("Refresh-token reuse detections (assumed theft)").register(registry);
        this.mfaActivations = Counter.builder("auth_mfa_activation_total")
                .description("MFA activations").register(registry);
        this.aiInsightTimer = Timer.builder("auth_ai_insight_duration")
                .description("Latency of AI security-insight generation").register(registry);
    }

    public void loginSuccess() { loginSuccess.increment(); }

    public void loginFailure(String reason) {
        Counter.builder("auth_login_failure_total")
                .description("Failed logins by reason")
                .tag("reason", reason)
                .register(registry)
                .increment();
    }

    public void accountLockout() { lockouts.increment(); }
    public void ipThrottled() { ipThrottled.increment(); }
    public void tokenReuseDetected() { tokenReuse.increment(); }
    public void mfaActivated() { mfaActivations.increment(); }
    public Timer aiInsightTimer() { return aiInsightTimer; }
}
