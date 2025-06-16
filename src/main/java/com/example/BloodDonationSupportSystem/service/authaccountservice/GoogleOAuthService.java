package com.example.BloodDonationSupportSystem.service.authaccountservice;


import com.example.BloodDonationSupportSystem.base.BaseReponse;
import com.example.BloodDonationSupportSystem.entity.OauthAccountEntity;
import com.example.BloodDonationSupportSystem.entity.RoleEntity;
import com.example.BloodDonationSupportSystem.entity.UserEntity;
import com.example.BloodDonationSupportSystem.repository.RoleRepository;
import com.example.BloodDonationSupportSystem.repository.UserRepository;
import com.example.BloodDonationSupportSystem.service.jwtservice.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;



@Slf4j
@Service
@RequiredArgsConstructor
@CrossOrigin("*")
public class GoogleOAuthService {

    private static final String GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    private static final String GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo";
    private static final String GOOGLE_PROVIDER = "google";

    @Value("${google.client.id}")
    private String clientId;

    @Value("${google.client.secret}")
    private String clientSecret;

    @Value("${google.redirect.uri}")
    private String redirectUri;


    private  RestTemplate restTemplate= new RestTemplate();

    @Autowired
    private final OauthService oauthService;
    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final AuthAccountService authAccountService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private RoleRepository roleRepository;

    public void redirectToGoogle(HttpServletResponse response) {
        try {
            String url = UriComponentsBuilder.fromHttpUrl(GOOGLE_AUTH_URL)
                    .queryParam("client_id", clientId)
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("response_type", "code")
                    .queryParam("scope", "openid email profile")
                    .queryParam("access_type", "offline")
                    .build().toUriString();
            response.sendRedirect(url);
        } catch (IOException e) {
            log.error("Error redirecting to Google", e);
            throw new RuntimeException("Failed to redirect to Google", e);
        }
    }

    public BaseReponse<?> handleGoogleCallback(String code) {
        try {
            String accessToken = getGoogleAccessToken(code);
            Map<String, Object> userInfo = getGoogleUserInfo(accessToken);

            String providerUserId = (String) userInfo.get("sub");

            var oauthAccountOpt = oauthService.getOauthAccount(GOOGLE_PROVIDER, providerUserId);
            UserEntity user = oauthAccountOpt.map(OauthAccountEntity::getUser)
                    .orElseGet(() -> createNewGoogleUser(userInfo, providerUserId));

            String jwtToken = jwtService.generateToken(
                    new org.springframework.security.core.userdetails.User(
                           user.getUserId().toString() , "", Collections.singletonList(new SimpleGrantedAuthority(user.getRole().getRoleName()))
                    )
            );


            return new BaseReponse<>(
                    HttpStatus.OK.value(),
                    "Login google successful",
                    jwtToken
            );
        } catch (Exception e) {
            return new BaseReponse<>(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Login failed: " + e.getMessage(),
                    null
            );
        }
    }

    private Map<String, Object> processGoogleUser(Map<String, Object> userInfo) {
        String providerUserId = (String) userInfo.get("sub");
        if (providerUserId == null) {
            throw new IllegalStateException("Invalid user info received from Google: no providerUserId");
        }

        var oauthAccountOpt = oauthService.getOauthAccount(GOOGLE_PROVIDER, providerUserId);
        UserEntity user = oauthAccountOpt.map(OauthAccountEntity::getUser)
                .orElseGet(() -> createNewGoogleUser(userInfo, providerUserId));

        Map<String, Object> result = new HashMap<>();
        result.put("name", user.getFullName());
        result.put("picture", userInfo.get("picture"));
        result.put("provider", GOOGLE_PROVIDER);
        result.put("provider_user_id", providerUserId);
        return result;
    }

    private UserEntity createNewGoogleUser(Map<String, Object> userInfo, String providerUserId) {


        UserEntity user = new UserEntity();
        user.setFullName((String) userInfo.get("name"));
        user.setStatus("KÍCH HOẠT");

        RoleEntity memberRole = roleRepository.findByRoleName("ROLE_MEMBER")
                .orElseThrow(() -> new RuntimeException("ROLE_MEMBER not found"));
        user.setRole(memberRole);
        user = userRepository.save(user);

        OauthAccountEntity oauthAccount = new OauthAccountEntity();
        oauthAccount.setProvider(GOOGLE_PROVIDER);
        oauthAccount.setProviderUserId(providerUserId);
        oauthAccount.setCreatedAt(LocalDateTime.now());
        oauthAccount.setAccount((String) userInfo.get("email"));
        oauthAccount.setUser(user);
        user.setOauthAccount(oauthAccount);
        oauthService.saveOauthAccount(oauthAccount);


        return user;
    }

    // Rest of the methods for token and user info retrieval remain the same
    // but moved to this service class
    private String getGoogleAccessToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    GOOGLE_TOKEN_URL,
                    request,
                    Map.class
            );

            if (!response.getStatusCode().is2xxSuccessful()) {
                log.error("Failed to get access token from Google. Status: {}", response.getStatusCode());
                throw new RuntimeException("Failed to get access token from Google");
            }

            Map<String, Object> body = response.getBody();
            if (body == null || !body.containsKey("access_token")) {
                log.error("No access_token found in Google's response");
                throw new RuntimeException("No access_token found in Google's response");
            }

            return (String) body.get("access_token");
        } catch (Exception e) {
            log.error("Error getting Google access token", e);
            throw new RuntimeException("Failed to get access token from Google", e);
        }
    }

    private Map<String, Object> getGoogleUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<?> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    GOOGLE_USER_INFO_URL,
                    HttpMethod.GET,
                    request,
                    Map.class
            );

            if (!response.getStatusCode().is2xxSuccessful()) {
                log.error("Failed to retrieve user info from Google. Status: {}", response.getStatusCode());
                throw new RuntimeException("Failed to retrieve user info from Google");
            }

            Map<String, Object> userInfo = response.getBody();
            if (userInfo == null) {
                log.error("User info response from Google is null");
                throw new RuntimeException("User info is null");
            }

            return userInfo;
        } catch (Exception e) {
            log.error("Error getting Google user info", e);
            throw new RuntimeException("Failed to retrieve user info from Google", e);
        }
    }
}
