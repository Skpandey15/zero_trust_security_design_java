package com.example.zerotrust.authserver.web;

import com.example.zerotrust.authserver.dto.AuthDtos.ApiError;
import com.example.zerotrust.authserver.dto.AuthDtos.StepUpError;
import com.example.zerotrust.authserver.service.AuthService.EmailAlreadyUsedException;
import com.example.zerotrust.authserver.service.AuthService.MfaAlreadyEnabledException;
import com.example.zerotrust.authserver.service.AuthService.MfaRequiredException;
import com.example.zerotrust.authserver.service.AuthService.StepUpRequiredException;
import com.example.zerotrust.authserver.service.LoginProtectionService.TooManyAttemptsException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailAlreadyUsedException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ApiError emailConflict(EmailAlreadyUsedException e) {
        return ApiError.of("EMAIL_TAKEN", e.getMessage());
    }

    /**
     * Two concurrent registrations can both pass the exists() check and race to
     * INSERT; the DB unique constraint rejects the loser. Map it to the same 409
     * a sequential duplicate would get, instead of a raw 500.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ApiError dataIntegrity(DataIntegrityViolationException e) {
        return ApiError.of("CONFLICT", "The request conflicts with existing data.");
    }

    @ExceptionHandler(MfaAlreadyEnabledException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ApiError mfaAlreadyEnabled(MfaAlreadyEnabledException e) {
        return ApiError.of("MFA_ALREADY_ENABLED", e.getMessage());
    }

    /** Validation failures on @RequestParam/@PathVariable (@Validated on the controller). */
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError constraintViolation(ConstraintViolationException e) {
        return ApiError.of("VALIDATION_FAILED", e.getMessage());
    }

    /**
     * Unparseable/absent request body. Handled here so it produces a JSON 400 in
     * the original dispatch — otherwise it forwards to /error, where the security
     * chain masks it as an empty 401/403 for anonymous callers on public routes.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError unreadable(HttpMessageNotReadableException e) {
        return ApiError.of("MALFORMED_REQUEST", "Request body is missing or not valid JSON.");
    }

    @ExceptionHandler({BadCredentialsException.class, DisabledException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiError badCredentials(Exception e) {
        return ApiError.of("UNAUTHORIZED", e.getMessage());
    }

    /** Password was correct but a TOTP code is required — client should prompt for it. */
    @ExceptionHandler(MfaRequiredException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiError mfaRequired(MfaRequiredException e) {
        return ApiError.of("MFA_REQUIRED", e.getMessage());
    }

    @ExceptionHandler(TooManyAttemptsException.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public ApiError tooManyAttempts(TooManyAttemptsException e) {
        return ApiError.of("RATE_LIMITED", e.getMessage());
    }

    /** Adaptive auth: a risky login needs a stronger factor (MFA) before it's allowed. */
    @ExceptionHandler(StepUpRequiredException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public StepUpError stepUp(StepUpRequiredException e) {
        return new StepUpError("STEP_UP_REQUIRED", e.getMessage(), java.time.Instant.now(),
                e.getStepUpToken(), e.getExpiresInSeconds());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError validation(MethodArgumentNotValidException e) {
        String details = e.getBindingResult().getFieldErrors().stream()
                .map(f -> f.getField() + ": " + f.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return ApiError.of("VALIDATION_FAILED", details);
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiError notFound(NoSuchElementException e) {
        return ApiError.of("NOT_FOUND", "Resource not found");
    }
}
