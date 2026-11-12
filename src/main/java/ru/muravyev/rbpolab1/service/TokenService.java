package ru.muravyev.rbpolab1.service;

import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.muravyev.rbpolab1.entity.SessionStatus;
import ru.muravyev.rbpolab1.entity.User;
import ru.muravyev.rbpolab1.entity.UserSession;
import ru.muravyev.rbpolab1.entity.UserStatus;
import ru.muravyev.rbpolab1.repository.UserRepository;
import ru.muravyev.rbpolab1.repository.UserSessionRepository;
import ru.muravyev.rbpolab1.security.InvalidTokenException;
import ru.muravyev.rbpolab1.security.JwtTokenProvider;
import ru.muravyev.rbpolab1.security.JwtTokenProvider.IssuedToken;

import java.time.Instant;

/**
 * Выдача и обновление пар access/refresh с серверным учётом refresh-сессий.
 */
@Service
public class TokenService {

    private final JwtTokenProvider jwt;
    private final UserSessionRepository sessionRepository;
    private final UserRepository userRepository;

    public record TokenPair(String accessToken, String refreshToken) {
    }

    public TokenService(JwtTokenProvider jwt,
                        UserSessionRepository sessionRepository,
                        UserRepository userRepository) {
        this.jwt = jwt;
        this.sessionRepository = sessionRepository;
        this.userRepository = userRepository;
    }

    // ---------------- Выдача пары ----------------

    /**
     * Вызывается после успешного входа или создания учётной записи.
     * Если вызвана внутри транзакции регистрации, выполняется в ней же:
     * не сохранилась сессия - не сохранится и пользователь.
     */
    @Transactional
    public TokenPair issuePair(User user, String deviceId) {
        IssuedToken access = jwt.createAccessToken(user);
        IssuedToken refresh = jwt.createRefreshToken(user);

        UserSession session = new UserSession();
        session.setUsername(user.getUsername());
        session.setDeviceId(deviceId);
        session.setAccessToken(access.token());
        session.setRefreshToken(refresh.token());
        session.setAccessTokenExpiry(access.expiresAt());
        session.setRefreshTokenExpiry(refresh.expiresAt());
        session.setStatus(SessionStatus.ACTIVE);

        // INSERT выполняется сейчас, а не при коммите:
        // пара возвращается только после того, как сессия реально записана
        sessionRepository.saveAndFlush(session);

        return new TokenPair(access.token(), refresh.token());
    }

    // ---------------- Обновление пары ----------------

    /**
     * noRollbackFor: при отказе по токену транзакция ФИКСИРУЕТСЯ,
     * чтобы пометка REVOKED (при повторном предъявлении) сохранилась.
     * Любая другая ошибка (например, сбой записи новой сессии) откатывает всё.
     */
    @Transactional(noRollbackFor = InvalidTokenException.class)
    public TokenPair refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("refreshToken is required"); // 400
        }

        // 1. JWT: подпись, срок, обязательные claims, type = refresh
        Claims claims = jwt.parseRefreshToken(refreshToken);

        // 2. Сессия, строка блокируется до конца транзакции
        UserSession session = sessionRepository.findByRefreshTokenForUpdate(refreshToken)
                .orElseThrow(() -> new InvalidTokenException("Unknown refresh session"));

        // 3. Токен принадлежит владельцу записи
        if (!session.getUsername().equals(claims.getSubject())) {
            throw new InvalidTokenException("Refresh token does not match the session");
        }

        // 4. Состояние сессии
        switch (session.getStatus()) {
            case REVOKED -> throw new InvalidTokenException("Refresh session is revoked");
            case USED -> {
                // повторное предъявление уже использованного refresh: отзываем сессию.
                // Изменение будет зафиксировано благодаря noRollbackFor.
                session.setStatus(SessionStatus.REVOKED);
                throw new InvalidTokenException("Refresh token has already been used");
            }
            case ACTIVE -> {
                // можно продолжать
            }
        }
        if (!session.getRefreshTokenExpiry().isAfter(Instant.now())) {
            throw new InvalidTokenException("Refresh token has expired");
        }

        // 5. Пользователь существует и не заблокирован
        User user = userRepository.findByUsername(session.getUsername())
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new InvalidTokenException("User is not allowed to refresh tokens"));

        // 6. Все проверки пройдены - только теперь меняем данные:
        //    старая сессия -> USED, новая пара -> новая сессия ACTIVE (та же транзакция)
        session.setStatus(SessionStatus.USED);
        return issuePair(user, session.getDeviceId());
    }
}