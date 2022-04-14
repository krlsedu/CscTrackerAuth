package com.csctracker.auth.configs;

import com.csctracker.auth.dto.AccessDeniedDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AccessDenied implements org.springframework.security.web.access.AccessDeniedHandler, AuthenticationFailureHandler, AuthenticationEntryPoint {

    public static void handler(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, String mensagem, HttpStatus httpStatus) throws IOException {
        handler(httpServletRequest, httpServletResponse, mensagem, httpStatus.value(), httpStatus.name());
    }

    public static void handler(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, String mensagem, Integer stautsCode, String statusName) throws IOException {
        httpServletResponse.setStatus(stautsCode);
        AccessDeniedDTO accessDeniedDTO = new AccessDeniedDTO();
        accessDeniedDTO.setStatus(stautsCode);
        accessDeniedDTO.setError(statusName);
        accessDeniedDTO.setMessage(mensagem);
        accessDeniedDTO.setPath(httpServletRequest.getServletPath());

        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
        httpServletResponse.setCharacterEncoding("UTF-8");

        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD, OPTIONS");
        httpServletResponse.setHeader("Access-Control-Allow-Origin", "*");

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonInString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(accessDeniedDTO);

        java.io.PrintWriter wr = httpServletResponse.getWriter();
        wr.write(jsonInString);
        wr.flush();
        wr.close();

    }

    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException {
        handler(httpServletRequest, httpServletResponse, "Access Denied", HttpStatus.FORBIDDEN);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
        handler(httpServletRequest, httpServletResponse, "User or password incorrect!", HttpStatus.UNAUTHORIZED);
    }

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
        if (e.getCause() instanceof OAuth2AccessDeniedException) {
            handler(httpServletRequest, httpServletResponse, e.getMessage(), HttpStatus.FORBIDDEN);
        } else {
            handler(httpServletRequest, httpServletResponse, "Token expired or invalid", HttpStatus.UNAUTHORIZED);
        }
    }
}