package com.example.zerotrust.resource;

import com.example.zerotrust.resource.authz.AccessExceptions.AuthorizationUnavailable;
import com.example.zerotrust.resource.authz.AccessExceptions.Forbidden;
import com.example.zerotrust.resource.authz.AccessExceptions.NotFound;
import com.example.zerotrust.resource.authz.AccessExceptions.StepUpRequired;
import com.example.zerotrust.resource.documents.Document.RuleViolation;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Maps authorization outcomes to responses. The messages are deliberately
 * generic: the specific reason is in the decision log (ADR-SEC-023), not in what
 * a caller can read back, so a refusal teaches an attacker nothing.
 */
@RestControllerAdvice
class ApiExceptionHandler {

    @ExceptionHandler(NotFound.class)
    ResponseEntity<Map<String, String>> notFound() {
        return body(HttpStatus.NOT_FOUND, "NOT_FOUND", "No such resource.");
    }

    @ExceptionHandler(Forbidden.class)
    ResponseEntity<Map<String, String>> forbidden() {
        return body(HttpStatus.FORBIDDEN, "FORBIDDEN", "You are not permitted to do this.");
    }

    /** RFC 9470: allowed in principle, but prove more first - and say so in the standard header. */
    @ExceptionHandler(StepUpRequired.class)
    ResponseEntity<Map<String, String>> stepUp() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .header(HttpHeaders.WWW_AUTHENTICATE,
                        "Bearer error=\"insufficient_user_authentication\", "
                                + "error_description=\"A second authentication factor is required\"")
                .body(Map.of("code", "STEP_UP_REQUIRED",
                        "message", "This needs a second authentication factor. Sign in with your authenticator code."));
    }

    @ExceptionHandler(RuleViolation.class)
    ResponseEntity<Map<String, String>> rule(RuleViolation e) {
        // A business rule, not a security detail: safe and useful to say.
        return body(HttpStatus.CONFLICT, "RULE_VIOLATION", e.getMessage());
    }

    /** Fail closed: no decision could be made, so nothing is permitted (ADR-SEC-024). */
    @ExceptionHandler(AuthorizationUnavailable.class)
    ResponseEntity<Map<String, String>> unavailable() {
        return body(HttpStatus.SERVICE_UNAVAILABLE, "AUTHORIZATION_UNAVAILABLE",
                "Authorization is temporarily unavailable. Try again shortly.");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<Map<String, String>> invalid() {
        return body(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "The request is not valid.");
    }

    private static ResponseEntity<Map<String, String>> body(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status).body(Map.of("code", code, "message", message));
    }
}
