package com.csctracker.auth.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenDTO {
    private String accessToken;
    private String refreshToken;
    private Integer expiresIn;

}
