package ru.muravyev.rbpolab1.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Читает "Authorization: Bearer <access>", проверяет access-токен
 * и сообщает Spring Security, кто выполняет запрос.
 * Принимает ТОЛЬКО access: refresh здесь будет отвергнут по claim "type".
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String PREFIX = "Bearer ";

    private final JwtTokenProvider jwt;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider jwt, UserDetailsService userDetailsService) {
        this.jwt = jwt;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith(PREFIX)) {
            String token = header.substring(PREFIX.length()).trim();
            try {
                Claims claims = jwt.parseAccessToken(token);
                // актуальное состояние пользователя - из БД, а не из токена
                UserDetails user = userDetailsService.loadUserByUsername(claims.getSubject());
                if (user.isAccountNonLocked() && user.isEnabled()) {
                    var authentication = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (InvalidTokenException | UsernameNotFoundException e) {
                // токен плохой - пользователь остаётся анонимным;
                // на защищённом адресе он получит 401
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(request, response);
    }
}