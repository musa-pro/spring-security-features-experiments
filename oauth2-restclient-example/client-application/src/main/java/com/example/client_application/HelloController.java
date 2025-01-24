package com.example.client_application;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

@RestController
public class HelloController {

    private final RestClient restClient;

    public HelloController(RestClient restClient){
        this.restClient = restClient;
    }
    @GetMapping("/hello")
    public String hello(){
        return this.restClient.get()
                .uri("http://localhost:8081/greet")
                .attributes(clientRegistrationId("oath2-test-client"))
                .retrieve()
                .body(String.class);
    }
}
