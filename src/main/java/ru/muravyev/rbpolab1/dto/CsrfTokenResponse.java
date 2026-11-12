package ru.muravyev.rbpolab1.dto;

public record CsrfTokenResponse(String headerName, String token) {
}