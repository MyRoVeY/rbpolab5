package ru.muravyev.rbpolab1.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.muravyev.rbpolab1.entity.User;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

/**
 * Создание и проверка JWT (HS256).
 * Access и refresh создаются и проверяются отдельными методами.
 */
@Component
public class JwtTokenProvider {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    private static final String ISSUER = "rbpolab1";
    private static final String CLAIM_TYPE = "type";

    private final SecretKey key;
    private final Duration accessTtl;
    private final Duration refreshTtl;

    // Выданный токен вместе с моментом истечения (он же уйдёт в БД)
    public record IssuedToken(String token, Instant expiresAt) {
    }

    public JwtTokenProvider(@Value("${jwt.secret}") String secretBase64,
                            @Value("${jwt.access-ttl}") Duration accessTtl,
                            @Value("${jwt.refresh-ttl}") Duration refreshTtl) {
        byte[] secret = Decoders.BASE64.decode(secretBase64);
        if (secret.length < 32) {
            // приложение не запустится со слабым ключом
            throw new IllegalStateException("JWT_SECRET must contain at least 32 bytes (Base64)");
        }
        this.key = Keys.hmacShaKeyFor(secret);
        this.accessTtl = accessTtl;
        this.refreshTtl = refreshTtl;
    }

    // ---------------- создание ----------------

    public IssuedToken createAccessToken(User user) {
        return create(user, TYPE_ACCESS, accessTtl);
    }

    public IssuedToken createRefreshToken(User user) {
        return create(user, TYPE_REFRESH, refreshTtl);
    }

    private IssuedToken create(User user, String type, Duration ttl) {
        // JWT хранит время с точностью до секунды, поэтому отбрасываем миллисекунды:
        // тогда срок в БД в точности совпадёт с exp внутри токена
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(ttl);

        String token = Jwts.builder()
                .id(UUID.randomUUID().toString())   // jti - новый для каждой выдачи
                .issuer(ISSUER)
                .subject(user.getUsername())
                .claim(CLAIM_TYPE, type)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
        return new IssuedToken(token, expiresAt);
    }

    // ---------------- проверка ----------------

    public Claims parseAccessToken(String token) {
        return parse(token, TYPE_ACCESS);
    }

    public Claims parseRefreshToken(String token) {
        return parse(token, TYPE_REFRESH);
    }

    private Claims parse(String token, String expectedType) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(key)          // подпись нашим ключом, только HMAC; "alg":"none" отвергается
                    .requireIssuer(ISSUER)    // выдан нашим приложением
                    .build()
                    .parseSignedClaims(token) // заодно проверяет exp: просроченный -> исключение
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            // подробности (почему именно) наружу не отдаём
            throw new InvalidTokenException("Invalid or expired token");
        }

        // обязательные claims
        if (isBlank(claims.getSubject()) || isBlank(claims.getId())
                || claims.getIssuedAt() == null || claims.getExpiration() == null) {
            throw new InvalidTokenException("Invalid or expired token");
        }
        // назначение токена
        if (!expectedType.equals(claims.get(CLAIM_TYPE, String.class))) {
            throw new InvalidTokenException("Invalid token type");
        }
        return claims;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}