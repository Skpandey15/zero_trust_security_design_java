package com.example.zerotrust.authserver.repository;

import com.example.zerotrust.authserver.domain.LoginAttempt;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, String> {

    /**
     * Fetch the counter row with a row-level write lock so two concurrent
     * failures for the same account serialize through the increment instead of
     * both reading a stale count (SELECT ... FOR UPDATE).
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select la from LoginAttempt la where la.email = :email")
    Optional<LoginAttempt> findForUpdate(@Param("email") String email);
}
