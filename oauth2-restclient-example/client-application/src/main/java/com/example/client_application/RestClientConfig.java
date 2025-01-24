package com.example.client_application;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

//    @Bean
//    public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
//                                                                 OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
//        /*
//         * note to self: we are creating this bean with AuthorizedClientServiceOAuth2AuthorizedClientManager because it allows
//         * self-contained auth without a pre-existing http session, by default a DefaultOAuth2AuthorizedClientManager is
//         * provided by spring security when asked to inject a OAuth2AuthorizedClientManager which requires a http request as input
//         * (i.e. it must be called via web) which is not suitable for schedules and so on
//         */
//        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
//                .refreshToken()
//                .clientCredentials()
//                .authorizationCode()
//                .build();
//        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
//                new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, oAuth2AuthorizedClientService);
//        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
//
//        return authorizedClientManager;
//    }

    @Bean
    public RestClient restClient(RestClient.Builder builder, OAuth2AuthorizedClientManager authorizedClientManager){
        OAuth2ClientHttpRequestInterceptor oauth2ClientHttpRequestInterceptor = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
        return builder
                .requestInterceptor(oauth2ClientHttpRequestInterceptor)
                .build();
    }

}
