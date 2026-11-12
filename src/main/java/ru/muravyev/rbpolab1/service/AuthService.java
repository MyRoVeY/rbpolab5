package ru.muravyev.rbpolab1.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.muravyev.rbpolab1.entity.User;
import ru.muravyev.rbpolab1.service.TokenService.TokenPair;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final TokenService tokenService;

    public AuthService(AuthenticationManager authenticationManager,
                       UserService userService,
                       TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.tokenService = tokenService;
    }

    // Вход: проверить логин/пароль/блокировку, выдать пару
    public TokenPair login(String username, String password, String deviceId) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalArgumentException("username and password are required"); // 400
        }
        // неверный пароль, нет пользователя или заблокирован -> AuthenticationException -> 401
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        User user = userService.getByUsername(username);
        return tokenService.issuePair(user, deviceId);
    }

    // Регистрация + выдача пары В ОДНОЙ транзакции:
    // если сессия не сохранится, пользователь тоже не будет создан
    @Transactional
    public TokenPair register(String username, String password, String name, String email,
                              String deviceId) {
        User user = userService.register(username, password, name, email); // все проверки задания 4
        return tokenService.issuePair(user, deviceId);
    }

    public TokenPair refresh(String refreshToken) {
        return tokenService.refresh(refreshToken);
    }
}