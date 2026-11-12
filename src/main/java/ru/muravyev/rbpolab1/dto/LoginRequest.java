package ru.muravyev.rbpolab1.dto;

public record LoginRequest(String username, String password, String deviceId) {
}