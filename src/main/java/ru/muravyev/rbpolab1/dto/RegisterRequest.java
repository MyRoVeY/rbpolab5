package ru.muravyev.rbpolab1.dto;

// Поля role здесь нет специально: при регистрации роль выбрать нельзя
public record RegisterRequest(String username, String password, String name, String email,
                              String deviceId) {
}