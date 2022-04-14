package com.csctracker.auth.configs;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@ControllerAdvice
public class UnAuthorized extends IllegalArgumentException {
	public UnAuthorized() {
		super();
	}

	public UnAuthorized(String s) {
		super(s);
	}

	public UnAuthorized(String message, Throwable cause) {
		super(message, cause);
	}

	@ExceptionHandler(UnAuthorized.class)
	void handleBadRequests(HttpServletResponse response) throws IOException {
		response.sendError(HttpStatus.UNAUTHORIZED.value());
	}
}
