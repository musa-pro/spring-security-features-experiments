package com.example.client_application;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.UUID;

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
                .queryParam("scope", "profile openid")
//                .queryParam("state", UUID.randomUUID().toString().replace("-", ""))
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .build()
                .toUriString();
        response.sendRedirect(authorizationUrl);
    }

    @GetMapping("/callback")
    public void callback(@RequestParam(value = "code", required = false) String code, @RequestParam(value = "state", required = false) String state,
                           @RequestParam(value = "error", required = false) String error,
                           @RequestParam(value = "error_description", required = false) String error_description){


        if (code != null) {
            HttpHeaders headers = new HttpHeaders();
//            headers.setBasicAuth(clientId, clientSecret);
//            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//
//            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
//            body.add("grant_type", "authorization_code");
//            body.add("code", authorizationCode);
//            body.add("redirect_uri", redirectUri);
//
//            OAuth2AccessToken accessToken = restClient.post()
//                    .uri("http://localhost:8080/oauth2/token")
//                    .headers(headers)
//                    .body(BodyInserters.fromValue(body))
//                    .retrieve()
//                    .bodyToMono(OAuth2AccessToken.class)
//                    .block();
            System.out.println("code: " + code);
        } else {
            System.out.println("error: " + error);
            System.out.println("error_description: " + error_description);
        }
    }
}
