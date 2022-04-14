package com.csctracker.auth.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import org.springframework.http.HttpStatus;

import java.util.Date;

public class AccessDeniedDTO {

    @JsonFormat(shape = JsonFormat.Shape.STRING)
    protected Date timestamp = new Date();

    private Integer status = HttpStatus.FORBIDDEN.value();

    private String error = HttpStatus.FORBIDDEN.name();

    private String message;

    private String path;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }


}

