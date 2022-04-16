package com.csctracker.auth.service;

import com.csctracker.auth.configs.ApiError;
import com.csctracker.auth.configs.TokenService;
import com.csctracker.auth.configs.UnAuthorized;
import com.csctracker.auth.dto.TokenDTO;
import com.csctracker.auth.dto.TokenGoogle;
import com.csctracker.auth.dto.UserDTO;
import com.csctracker.auth.enums.UserType;
import com.csctracker.auth.model.User;
import com.csctracker.auth.repository.UserRepository;
import com.csctracker.auth.utils.Conversor;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Tokeninfo;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.*;
import org.springframework.stereotype.Service;

import javax.servlet.ServletException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

@Service("userService")
public class UserService implements UserDetailsService {
    //private static final String APPLICATION_NAME = "GRP TESTE CLIENTE";
    private final String APPLICATION_NAME = "CscTracker";
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final ClientDetailsService clientDetailsService;
    private final Conversor<User, UserDTO> conversor;
    @Value("${url.ouathServer}")
    private String SERVER_URL;
    @Value("${oauth-client_id}")
    private String CLIENT_ID;
    @Value("${oauth-secret}")
    private String SECRET;

    public UserService(UserRepository userRepository, TokenService tokenService, ClientDetailsService clientDetailsService) {
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.clientDetailsService = clientDetailsService;
        this.conversor = new Conversor<>(User.class, UserDTO.class);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User usuario = userRepository.findByEmail(email);
        if (usuario != null) {
            return new org.springframework.security.core.userdetails.User(email, usuario.getPassword(), Collections.singletonList(new SimpleGrantedAuthority(usuario.getType().getKey())));
        } else {
            throw new UnAuthorized("User or password invalid!");
        }
    }

    public TokenGoogle getTokenGoogle(String code, String url) {

        TokenGoogle json = new TokenGoogle();

        if (url == null) {
            json.setRedirect_uri(SERVER_URL + "/oauth");
            System.out.println("URL: " + json.getRedirect_uri());
        } else {
            json.setRedirect_uri(url);
        }
        json.setGrant_type("authorization_code");
        json.setClient_secret(SECRET);
        json.setClient_id(CLIENT_ID);
        json.setAccess_type("offline");
        json.setCode(code);

        try {
            return getTokenGoogle(json);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        throw new UnAuthorized("Error on Oauth!");
    }

    private TokenGoogle getTokenGoogle(TokenGoogle json) throws IOException, UnirestException {
        return getTokenGoogle(json, true);
    }

    private TokenGoogle getTokenGoogle(TokenGoogle json, boolean tr) throws IOException, UnirestException {

        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        ObjectMapper mapperRead = new ObjectMapper();
        mapperRead.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        var response = Unirest.post("https://www.googleapis.com/oauth2/v4/token")
                .header("Content-Type", "application/json")
                .body(mapper.writeValueAsString(json))
                .asString();
        TokenGoogle tokenGoogle = mapperRead.readValue(response.getBody(), TokenGoogle.class);
        if (tokenGoogle.getError() != null) {
            if (tr)
                throw new UnAuthorized("Error on Oauth! " + tokenGoogle.getError() + " - " + tokenGoogle.getError_description());
            return null;
        }
        return tokenGoogle;
    }

    public String getEmail(String accessToken) {
        GoogleCredential credential = new GoogleCredential().setAccessToken(accessToken);
        Oauth2 oauth2 = new Oauth2.Builder(
                new NetHttpTransport(), new JacksonFactory(), credential).setApplicationName(APPLICATION_NAME).build();
        try {
            Tokeninfo tokenInfo = oauth2.tokeninfo()
                    .setAccessToken(accessToken).execute();
            if (tokenInfo.getIssuedTo().equals(CLIENT_ID)) {
                return tokenInfo.getEmail();
            }
        } catch (IOException e) {
            //IGNORED
        }
        throw new UnAuthorized("Error on Oauth!");
    }

    private TokenDTO getAccessToken(String clientId, User user) {
        HashMap<String, String> authorizationParameters = new HashMap<>();
        authorizationParameters.put("scope", "read write trust");
        authorizationParameters.put("username", user.getEmail());
        authorizationParameters.put("client_id", clientId);
        authorizationParameters.put("grant", "password");

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority(user.getType().getKey()));

        Set<String> responseType = new HashSet<>();
        responseType.add("password");

        ClientDetails clientDetails = getClientDetails(clientId);
        Set<String> resIds = clientDetails.getResourceIds();

        OAuth2Request authorizationRequest = new OAuth2Request(
                authorizationParameters, clientId,
                clientDetails.getAuthorities(), true, clientDetails.getScope(), resIds, "",
                responseType, null);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                user.getEmail(), user.getPassword(), authorities);

        OAuth2Authentication authenticationRequest = new OAuth2Authentication(
                authorizationRequest, authenticationToken);

        OAuth2AccessToken accessToken = tokenService
                .createAccessToken(authenticationRequest);

        return tokenToTokenDTO(accessToken);
    }

    private TokenDTO tokenToTokenDTO(OAuth2AccessToken accessToken) {
        accessToken.getValue();

        TokenDTO tokenDTO = new TokenDTO();

        tokenDTO.setAccessToken(accessToken.getValue());
        tokenDTO.setRefreshToken(accessToken.getRefreshToken().getValue());
        tokenDTO.setExpiresIn(accessToken.getExpiresIn());

        return tokenDTO;
    }

    private ClientDetails getClientDetails(String clientId) {
        ClientDetails clientDetails;
        try {
            clientDetails = clientDetailsService.loadClientByClientId(clientId);
            tokenService.setAccessTokenValiditySeconds(clientDetails.getAccessTokenValiditySeconds());
        } catch (ClientRegistrationException e) {
            throw new ApiError("Error on Oauth!");
        }
        return clientDetails;
    }

    public UserDTO oauthG(String autorazationCode, String url) throws ServletException, IOException, NoSuchAlgorithmException {

        TokenGoogle token = getTokenGoogle(autorazationCode, url);

        if (token == null) {
            throw new UnAuthorized("Error on Oauth!");
        }

        UserDTO userDTO = new UserDTO();
        userDTO.setEmail(getEmail(token.getAccess_token()));

        return oauth(userDTO);
    }

    public UserDTO oauth(UserDTO userDTO) {

        if (userDTO.getEmail() == null) {
            throw new ApiError("User and password required!");
        }
        User user = conversor.toU(userDTO);
        if (user.getType() == null) {
            user.setType(UserType.USER);
        }

        User userAuth = userRepository.findByEmail(user.getEmail());

        if (userAuth == null) {
            userAuth = userRepository.save(user);
        }

        userDTO = conversor.toT(userAuth);

        TokenDTO tokenDTO = getAccessToken("OAUTH", userAuth);
        userDTO.setToken(tokenDTO);

        return userDTO;
    }

    public UserDTO getAuth(UserDTO usuarioDTO, String autorazationCode, String url, String tokenGoogleSt) {
        String token = null;
        if (autorazationCode != null) {
            TokenGoogle tokenGoogle = getTokenGoogle(autorazationCode, url);
            token = tokenGoogle.getAccess_token();
            usuarioDTO = new UserDTO();
            usuarioDTO.setEmail(getEmail(token));
        } else {
            if (tokenGoogleSt != null) {
                usuarioDTO = new UserDTO();
                usuarioDTO.setEmail(getEmail(tokenGoogleSt));
                token = tokenGoogleSt;
            }
        }

        if (token == null) {
            throw new UnAuthorized("Error on Oauth!");
        }
        return oauth(usuarioDTO);
    }
}
