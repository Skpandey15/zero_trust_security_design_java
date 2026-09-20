package com.example.zerotrust.authserver.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "login_audit")
public class LoginAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 320)
    private String email;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt = Instant.now();

    protected LoginAudit() {}

    public LoginAudit(String email, String ipAddress, String userAgent, boolean success) {
        this.email = email;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.success = success;
    }

    public String getEmail() { return email; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }
    public boolean isSuccess() { return success; }
    public Instant getOccurredAt() { return occurredAt; }
}
