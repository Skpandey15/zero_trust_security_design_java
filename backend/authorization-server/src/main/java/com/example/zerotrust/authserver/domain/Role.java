package com.example.zerotrust.authserver.domain;

import java.util.Set;

/** Roles are just named bundles of permissions (RBAC over permissions). */
public enum Role {
    USER(Set.of(
            Permission.PROFILE_READ)),
    ADMIN(Set.of(
            Permission.PROFILE_READ,
            Permission.USERS_READ,
            Permission.USERS_MANAGE,
            Permission.SECURITY_INSIGHTS));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> permissions() {
        return permissions;
    }
}
