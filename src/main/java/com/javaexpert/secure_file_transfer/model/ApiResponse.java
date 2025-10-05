package com.javaexpert.secure_file_transfer.model;

import java.time.LocalDateTime;

/**
 * A standard class for creating API responses.
 * This helps in sending a consistent JSON structure back to the client.
 */
public class ApiResponse {

    private final String message;
    private final LocalDateTime timestamp;

    public ApiResponse(String message) {
        this.message = message;
        this.timestamp = LocalDateTime.now();
    }

    // Getters are required for Spring Boot's JSON serializer (Jackson) to work.
    public String getMessage() {
        return message;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}