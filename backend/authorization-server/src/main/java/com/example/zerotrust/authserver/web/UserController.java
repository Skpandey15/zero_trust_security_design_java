package com.example.zerotrust.authserver.web;

import com.example.zerotrust.authserver.dto.AuthDtos.UserResponse;
import com.example.zerotrust.authserver.repository.UserRepository;
import com.example.zerotrust.authserver.service.AuthService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /** Any authenticated user can read their own profile. */
    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return userRepository.findByEmailIgnoreCase(jwt.getSubject())
                .map(AuthService::toResponse)
                .orElseThrow(() -> new UsernameNotFoundException(jwt.getSubject()));
    }
}
