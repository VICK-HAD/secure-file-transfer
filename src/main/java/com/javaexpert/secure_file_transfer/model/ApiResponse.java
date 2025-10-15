package com.javaexpert.secure_file_transfer.model;

import java.time.LocalDateTime;

public class ApiResponse {

    private final String message;
    private final LocalDateTime timestamp;

    public ApiResponse(String message) {
        this.message = message;
        this.timestamp = LocalDateTime.now();
    }

    public String getMessage() {
        return message;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}