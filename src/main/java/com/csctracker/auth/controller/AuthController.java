package com.csctracker.auth.controller;

import com.csctracker.auth.dto.UserDTO;
import com.csctracker.auth.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@RestController
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/oauth")
    public ResponseEntity<UserDTO> oauthG(@RequestParam(value = "code", required = false) String autorazationCode,
                                          @RequestParam(value = "redirect_uri", required = false) String url) throws ServletException, IOException, NoSuchAlgorithmException {
        return new ResponseEntity<>(userService.oauthG(autorazationCode, url), HttpStatus.OK);
    }

    @PostMapping("/oauth")
    public ResponseEntity<UserDTO> oauth(@RequestBody UserDTO usuarioDTO,
                                         @RequestParam(value = "code", required = false) String autorazationCode,
                                         @RequestParam(value = "redirect_uri", required = false) String url,
                                         @RequestParam(value = "tokenGoogle", required = false) String tokenGoogleSt) {

        return new ResponseEntity<>(userService.getAuth(usuarioDTO, autorazationCode, url, tokenGoogleSt), HttpStatus.OK);
    }
}
