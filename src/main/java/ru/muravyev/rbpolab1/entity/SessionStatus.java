package ru.muravyev.rbpolab1.entity;

public enum SessionStatus {
    ACTIVE,   // refresh ещё не использован и не отозван
    USED,     // refresh успешно обменян на новую пару
    REVOKED   // refresh отозван
}