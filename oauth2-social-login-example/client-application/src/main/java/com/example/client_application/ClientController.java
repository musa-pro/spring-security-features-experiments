package com.example.client_application;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.UUID;

import static org.springframework.http.MediaType.MULTIPART_FORM_DATA_VALUE;

@RestController
public class ClientController {

    private final RestClient restClient;

    public ClientController(RestClient restClient) {
        this.restClient = restClient;
    }

    @GetMapping("/auth")
    public void initiateAuth(HttpServletResponse response) throws IOException {

        // Generate and store code verifier
        String codeVerifier = PKCEUtil.generateCodeVerifier();
//        session.setAttribute("codeVerifier", codeVerifier);

        // Generate code challenge
        String codeChallenge = PKCEUtil.generateCodeChallenge(codeVerifier);

        String authorizationUrl = UriComponentsBuilder
                .fromUriString("http://localhost:8080/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", "public-client")
                .queryParam("redirect_uri", "http://localhost:3000/callback")
                .queryParam("scope", "profile openid read write")
                .queryParam("state", UUID.randomUUID().toString().replace("-", ""))
//                .queryParam("code_challenge", codeChallenge)
//                .queryParam("code_challenge_method", "S256")
                .build()
                .toUriString();
        response.sendRedirect(authorizationUrl);
    }

    @GetMapping("/callback")
    public ResponseEntity<String> callback(@RequestParam(value = "code", required = false) String authorizationCode, @RequestParam(value = "state", required = false) String state,
                                                      @RequestParam(value = "error", required = false) String error,
                                                      @RequestParam(value = "error_description", required = false) String error_description){


        if (authorizationCode != null) {
            HttpHeaders headers = new HttpHeaders();
            headers.setBasicAuth("public-client", "secret");
            headers.setContentType(MediaType.valueOf(MULTIPART_FORM_DATA_VALUE));


            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "authorization_code");
            formData.add("code", authorizationCode);
            formData.add("redirect_uri", "http://localhost:3000/callback");
//            body.add("state", state);

            try{
                ResponseEntity<String> response = restClient.post()
                        .uri("http://localhost:8080/oauth2/token")
                        .headers(h -> {
                            h.addAll(headers);
                        })
                        .body(formData)
                        .retrieve()
                        .toEntity(String.class);
                return ResponseEntity.ok(response.getBody());

            }catch (Exception e){
                e.printStackTrace();
                return ResponseEntity.ok(null);
            }

        } else {
            System.out.println("error: " + error);
            System.out.println("error_description: " + error_description);
            return ResponseEntity.ok(null);
        }
    }
}
