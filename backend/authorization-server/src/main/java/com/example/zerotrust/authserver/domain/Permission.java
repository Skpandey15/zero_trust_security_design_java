package com.example.zerotrust.authserver.domain;

/** Fine-grained permissions — the unit of authorization (least privilege). */
public enum Permission {
    PROFILE_READ("profile:read"),
    USERS_READ("users:read"),
    USERS_MANAGE("users:manage"),
    SECURITY_INSIGHTS("security:insights");

    private final String value;

    Permission(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
