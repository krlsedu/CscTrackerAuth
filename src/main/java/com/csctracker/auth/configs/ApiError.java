package com.csctracker.auth.configs;

import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;


@ControllerAdvice
@Component
public class ApiError extends IllegalArgumentException {
    public ApiError() {
        super();
    }

    public ApiError(String s) {
        super(s);
    }

    public ApiError(String message, Throwable cause) {
        super(message, cause);
    }
}


