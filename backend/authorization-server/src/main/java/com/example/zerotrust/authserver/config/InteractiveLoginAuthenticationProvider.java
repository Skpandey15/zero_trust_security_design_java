package com.example.zerotrust.authserver.config;

import com.example.zerotrust.authserver.service.AuthService;
import com.example.zerotrust.authserver.service.AuthService.VerifiedLogin;
import com.example.zerotrust.authserver.service.LoginProtectionService.TooManyAttemptsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Authenticates the interactive sign-in page through the SAME pipeline as the
 * token API - lockout, per-IP throttle, Argon2id with a timing equaliser, and a
 * mandatory, single-use TOTP code once the account has enrolled one.
 *
 * <p>The page used to authenticate with Spring's stock username/password
 * provider, so an account that had switched on two-step verification could
 * still sign in here with a password alone. That made the second factor
 * decorative: an attacker with the password simply used this door.
 *
 * <p>Every failure - unknown user, wrong password, missing or wrong code,
 * locked account - is reported identically, so the page reveals neither whether
 * an account exists nor whether it has two-step verification.
 */
@Component
public class InteractiveLoginAuthenticationProvider implements AuthenticationProvider {

    private static final Logger secLog = LoggerFactory.getLogger("security.events");

    /** Granted to a session that authenticated with a password (RFC 8176 amr "pwd"). */
    public static final String FACTOR_PASSWORD = FactorGrantedAuthority.PASSWORD_AUTHORITY;
    /** Granted when a TOTP code was also verified (RFC 8176 amr "otp"). Spring has no TOTP constant. */
    public static final String FACTOR_TOTP = "FACTOR_TOTP";

    /** What the sign-in form submitted besides the credentials. */
    public record LoginDetails(String ip, String userAgent, String otp) {}

    private final AuthService authService;

    public InteractiveLoginAuthenticationProvider(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginDetails details = authentication.getDetails() instanceof LoginDetails d
                ? d : new LoginDetails(null, null, null);
        String password = authentication.getCredentials() == null ? "" : authentication.getCredentials().toString();

        VerifiedLogin verified;
        try {
            verified = authService.verifyCredentials(authentication.getName(), password, details.otp(),
                    details.ip(), details.userAgent(), false);
        } catch (TooManyAttemptsException e) {
            secLog.warn("event=interactive_login_refused reason=throttled ip={}", details.ip());
            throw new BadCredentialsException("Sign-in failed");
        } catch (RuntimeException e) {
            // Bad credentials, missing code and wrong code are deliberately indistinguishable.
            throw new BadCredentialsException("Sign-in failed");
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        verified.user().getRoles().forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r.name())));
        // FactorGrantedAuthority, not a plain string: it carries WHEN the factor was
        // proved, and the Authorization Server derives the ID token's auth_time from
        // it. A plain "FACTOR_PASSWORD" authority has no time, and issuing an ID
        // token then fails outright.
        authorities.add(FactorGrantedAuthority.fromAuthority(FACTOR_PASSWORD));
        if (verified.otpUsed()) {
            authorities.add(FactorGrantedAuthority.fromAuthority(FACTOR_TOTP));
        }

        User principal = new User(verified.user().getEmail(), "", authorities);
        UsernamePasswordAuthenticationToken result =
                UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities);
        result.setDetails(details);
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
