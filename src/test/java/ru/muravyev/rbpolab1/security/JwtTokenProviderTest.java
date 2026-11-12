package ru.muravyev.rbpolab1.security;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import ru.muravyev.rbpolab1.entity.User;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

    private static String randomSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static User user(String username) {
        User u = new User();
        u.setUsername(username);
        return u;
    }

    private final JwtTokenProvider provider =
            new JwtTokenProvider(randomSecret(), Duration.ofMinutes(15), Duration.ofDays(7));

    @Test
    void accessTokenIsValidAsAccess() {
        String token = provider.createAccessToken(user("maria")).token();
        Claims claims = provider.parseAccessToken(token);
        assertEquals("maria", claims.getSubject());
        assertEquals("access", claims.get("type", String.class));
    }

    @Test
    void accessTokenIsRejectedAsRefresh() {
        String access = provider.createAccessToken(user("maria")).token();
        assertThrows(InvalidTokenException.class, () -> provider.parseRefreshToken(access));
    }

    @Test
    void refreshTokenIsRejectedAsAccess() {
        String refresh = provider.createRefreshToken(user("maria")).token();
        assertThrows(InvalidTokenException.class, () -> provider.parseAccessToken(refresh));
    }

    @Test
    void eachTokenHasNewJti() {
        String t1 = provider.createRefreshToken(user("maria")).token();
        String t2 = provider.createRefreshToken(user("maria")).token();
        assertNotEquals(t1, t2);
        assertNotEquals(provider.parseRefreshToken(t1).getId(), provider.parseRefreshToken(t2).getId());
    }

    @Test
    void expiryMatchesExpClaimToTheSecond() {
        JwtTokenProvider.IssuedToken issued = provider.createAccessToken(user("maria"));
        Claims claims = provider.parseAccessToken(issued.token());
        assertEquals(issued.expiresAt(), claims.getExpiration().toInstant());
    }

    @Test
    void expiredTokenIsRejected() {
        JwtTokenProvider expiredProvider =
                new JwtTokenProvider(randomSecret(), Duration.ofSeconds(-60), Duration.ofDays(7));
        String token = expiredProvider.createAccessToken(user("maria")).token();
        assertThrows(InvalidTokenException.class, () -> expiredProvider.parseAccessToken(token));
    }

    @Test
    void tokenSignedWithAnotherKeyIsRejected() {
        JwtTokenProvider stranger =
                new JwtTokenProvider(randomSecret(), Duration.ofMinutes(15), Duration.ofDays(7));
        String foreign = stranger.createAccessToken(user("admin")).token();
        assertThrows(InvalidTokenException.class, () -> provider.parseAccessToken(foreign));
    }

    @Test
    void tamperedPayloadIsRejected() {
        String[] parts = provider.createAccessToken(user("maria")).token().split("\\.");
        // подменяем payload: пытаемся стать admin, подпись оставляем старую
        String fakePayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"iss\":\"rbpolab1\",\"sub\":\"admin\",\"type\":\"access\",\"jti\":\"x\",\"iat\":1,\"exp\":9999999999}"
                        .getBytes());
        String forged = parts[0] + "." + fakePayload + "." + parts[2];
        assertThrows(InvalidTokenException.class, () -> provider.parseAccessToken(forged));
    }

    @Test
    void garbageIsRejected() {
        assertThrows(InvalidTokenException.class, () -> provider.parseAccessToken("not-a-jwt"));
        assertThrows(InvalidTokenException.class, () -> provider.parseAccessToken(""));
    }

    @Test
    void shortSecretIsNotAccepted() {
        String shortSecret = Base64.getEncoder().encodeToString("too-short".getBytes());
        assertThrows(IllegalStateException.class,
                () -> new JwtTokenProvider(shortSecret, Duration.ofMinutes(15), Duration.ofDays(7)));
    }
}