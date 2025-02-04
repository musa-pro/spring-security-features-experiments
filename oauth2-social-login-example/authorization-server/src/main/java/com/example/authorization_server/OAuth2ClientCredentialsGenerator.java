package com.example.authorization_server;

import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class OAuth2ClientCredentialsGenerator {
    private static final int CLIENT_ID_LENGTH = 32;
    private static final String CLIENT_ID_SUFFIX = ".akkadiax.tr.com";
    private static final int CLIENT_SECRET_LENGTH = 64;

    private final SecureRandom secureRandom;

    public OAuth2ClientCredentialsGenerator() {
        try {
            this.secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("Failed to initialize secure random", e);
        }
    }

    public record ClientCredentials(String clientId, String clientSecret) {}

    public ClientCredentials generateCredentials() {
        String clientId = generateClientId() + CLIENT_ID_SUFFIX;
        String clientSecret = generateClientSecret();
        return new ClientCredentials(clientId, clientSecret);
    }

    private String generateClientId() {
        byte[] bytes = new byte[CLIENT_ID_LENGTH];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateClientSecret() {
        byte[] bytes = new byte[CLIENT_SECRET_LENGTH];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

