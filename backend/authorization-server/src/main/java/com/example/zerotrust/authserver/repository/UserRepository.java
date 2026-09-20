package com.example.zerotrust.authserver.repository;

import com.example.zerotrust.authserver.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Exact-match lookups. Emails are normalized to lower case before they are
     * ever stored (see AuthService.normalize), so equality here uses the plain
     * UNIQUE index on users.email — unlike the IgnoreCase variants, whose
     * lower(email)=lower(?) predicate forces a full scan on Postgres.
     */
    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<User> findByEmailIgnoreCase(String email);
}
