package com.example.zerotrust.authserver.web;

import com.example.zerotrust.authserver.dto.AuthDtos.UserResponse;
import com.example.zerotrust.authserver.repository.UserRepository;
import com.example.zerotrust.authserver.service.AuthService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserRepository userRepository;
    private final AuthService authService;

    public AdminController(UserRepository userRepository, AuthService authService) {
        this.userRepository = userRepository;
        this.authService = authService;
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('users:read')")
    public Page<UserResponse> listUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(AuthService::toResponse);
    }

    @PatchMapping("/users/{id}/disable")
    @PreAuthorize("hasAuthority('users:manage')")
    public UserResponse disable(@PathVariable Long id) {
        // Delegates to the service so disabling also revokes refresh tokens —
        // otherwise a disabled user keeps minting access tokens via /refresh.
        return authService.disableUser(id);
    }
}
