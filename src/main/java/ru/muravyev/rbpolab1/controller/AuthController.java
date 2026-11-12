package ru.muravyev.rbpolab1.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.muravyev.rbpolab1.dto.*;
import ru.muravyev.rbpolab1.entity.User;
import ru.muravyev.rbpolab1.service.AuthService;
import ru.muravyev.rbpolab1.service.TokenService.TokenPair;
import ru.muravyev.rbpolab1.service.UserService;

import java.security.Principal;

@RestController
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@RequestBody LoginRequest r) {
        return toResponse(authService.login(r.username(), r.password(), r.deviceId()));
    }

    @PostMapping("/auth/register")
    public ResponseEntity<TokenResponse> register(@RequestBody RegisterRequest r) {
        TokenPair pair = authService.register(r.username(), r.password(), r.name(), r.email(), r.deviceId());
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(pair));
    }

    @PostMapping("/auth/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest r) {
        return toResponse(authService.refresh(r.refreshToken()));
    }

    @GetMapping("/api/auth/me")
    public UserResponse me(Principal principal) {
        User u = userService.getByUsername(principal.getName());
        return new UserResponse(u.getId(), u.getUsername(), u.getName(), u.getEmail(),
                u.getRole(), u.getStatus(), u.getCreatedAt());
    }

    private TokenResponse toResponse(TokenPair pair) {
        return new TokenResponse(pair.accessToken(), pair.refreshToken());
    }
}