package com.csctracker.auth.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum UserType {
    USER("USER", "USER"),
    ADMIN("ADMIN", "ADMIN"),
    API("API", "API");

    private String key;

    private String description;

    UserType(String key, String description) {
        this.key = key;
        this.description = description;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @JsonValue
    public String getValor() {
        switch (this) {
            case ADMIN:
            case API:
            case USER:
                return getKey();
        }
        return "Invalid";
    }
}