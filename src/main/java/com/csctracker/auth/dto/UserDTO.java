package com.csctracker.auth.dto;

import com.csctracker.enums.UserType;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {
    private Long id;
    private String email;
    private String password;
    private UserType type;
    private TokenDTO token;
}
