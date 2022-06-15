package com.csctracker.auth.configs;

import com.csctracker.configs.RequestInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

@Component
public class SecureRequestInterceptor extends GenericFilterBean {

    public SecureRequestInterceptor() {
        RequestInterceptor.SECURE_REQUEST = true;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(servletRequest, servletResponse);
    }
}
