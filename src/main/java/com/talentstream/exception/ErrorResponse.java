package com.talentstream.exception;

public class ErrorResponse {
    private final String message;
    private final int statusCode;
    private final String status;

    public ErrorResponse(String message, int statusCode, String status) {
        this.message = message;
        this.statusCode = statusCode;
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getStatus() {
        return status;
    }
}

