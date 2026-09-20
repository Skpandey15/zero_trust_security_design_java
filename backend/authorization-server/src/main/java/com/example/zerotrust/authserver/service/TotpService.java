package com.example.zerotrust.authserver.service;

import org.bouncycastle.util.encoders.Base32;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * RFC 6238 TOTP (the algorithm behind Google Authenticator / Authy / 1Password),
 * implemented directly on the JDK — no extra dependency. 6 digits, 30-second
 * step, SHA-1, with a ±1 step window for clock drift.
 */
@Service
public class TotpService {

    private static final int DIGITS = 6;
    private static final int STEP_SECONDS = 30;

    private final SecureRandom secureRandom = new SecureRandom();

    /** 160-bit random secret, Base32-encoded for authenticator apps. */
    public String generateSecret() {
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return Base32.toBase32String(bytes);
    }

    /** otpauth:// URI — encode as a QR code and scan with any authenticator app. */
    public String provisioningUri(String secret, String accountEmail) {
        String issuer = TokenService.ISSUER;
        return "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d".formatted(
                issuer,
                URLEncoder.encode(accountEmail, StandardCharsets.UTF_8),
                secret, issuer, DIGITS, STEP_SECONDS);
    }

    public long currentTimeStep() {
        return Instant.now().getEpochSecond() / STEP_SECONDS;
    }

    /** True if the code is valid for the current ±1-step window. */
    public boolean verify(String secret, String code) {
        return verifyAndGetStep(secret, code) >= 0;
    }

    /**
     * Constant-time verification across the ±1-step window. Returns the matched
     * time-step (so callers can enforce single-use / replay protection), or -1
     * if no step in the window matches.
     */
    public long verifyAndGetStep(String secret, String code) {
        if (secret == null || code == null || code.length() != DIGITS) {
            return -1;
        }
        long currentStep = currentTimeStep();
        long matched = -1;
        for (long offset = -1; offset <= 1; offset++) {
            long step = currentStep + offset;
            if (constantTimeEquals(generateCode(secret, step), code)) {
                matched = step;   // no early return: keep the comparison count fixed
            }
        }
        return matched;
    }

    /** Public so tests and recovery tooling can derive the current code. */
    public String generateCode(String base32Secret, long timeStep) {
        byte[] key = Base32.decode(base32Secret.trim().toUpperCase());
        byte[] counter = new byte[8];
        for (int i = 7; i >= 0; i--) {
            counter[i] = (byte) (timeStep & 0xFF);
            timeStep >>= 8;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(counter);
            int dynOffset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[dynOffset] & 0x7F) << 24)
                    | ((hash[dynOffset + 1] & 0xFF) << 16)
                    | ((hash[dynOffset + 2] & 0xFF) << 8)
                    | (hash[dynOffset + 3] & 0xFF);
            int otp = binary % 1_000_000;
            return String.format("%06d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("TOTP generation failed", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
