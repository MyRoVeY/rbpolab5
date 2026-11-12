package ru.muravyev.rbpolab1.security;

// Токен недействителен: подпись, срок, claims, тип или состояние сессии.
// Превращается в ответ 401.
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}