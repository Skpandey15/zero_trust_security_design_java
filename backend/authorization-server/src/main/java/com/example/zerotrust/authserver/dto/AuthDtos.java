package com.example.zerotrust.authserver.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Set;

public final class AuthDtos {

    private AuthDtos() {}

    public record RegisterRequest(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Size(min = 12, max = 128) String password,
            @NotBlank @Size(max = 120) String displayName) {}

    public record LoginRequest(
            @NotBlank @Email String email,
            @NotBlank String password,
            @Pattern(regexp = "\\d{6}", message = "must be a 6-digit code") String otpCode) {}

    public record RefreshRequest(@NotBlank String refreshToken) {}

    public record MfaActivateRequest(
            @NotBlank @Pattern(regexp = "\\d{6}", message = "must be a 6-digit code") String code) {}

    public record MfaSetupResponse(String secret, String otpauthUri) {}

    public record TokenResponse(
            String accessToken,
            String refreshToken,
            String tokenType,
            long expiresInSeconds) {}

    public record UserResponse(
            Long id,
            String email,
            String displayName,
            Set<String> roles,
            boolean mfaEnabled,
            Instant createdAt) {}

    /**
     * STEP_UP_REQUIRED carries the enrolment token, so the client has an actionable
     * path out instead of a dead end. Shape is a superset of ApiError.
     */
    public record StepUpError(
            String code,
            String message,
            Instant timestamp,
            String stepUpToken,
            long expiresInSeconds) {}

    public record ApiError(String code, String message, Instant timestamp) {
        public static ApiError of(String code, String message) {
            return new ApiError(code, message, Instant.now());
        }
    }
}
