package com.example.authorization_server;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }

//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    private static KeyPair generateRsaKey() {
//        KeyPair keyPair;
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            keyPair = keyPairGenerator.generateKeyPair();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return keyPair;
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }


//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
//            throws Exception {
////        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());
//
//        http
//                .cors(Customizer.withDefaults())
//                .csrf(csrf -> csrf.ignoringRequestMatchers("/token", "/authorize"))
//                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//
//        return http.build();
//    }




//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    private static KeyPair generateRsaKey() {
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            return keyPairGenerator.generateKeyPair();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }

        @Bean
        @Order(1)
        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
                throws Exception {
            OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                    OAuth2AuthorizationServerConfigurer.authorizationServer();

            http
                    .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                    .with(authorizationServerConfigurer, (authorizationServer) ->
                            authorizationServer
                                    .oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
                    )
                    .authorizeHttpRequests((authorize) ->
                            authorize
                                    .anyRequest().authenticated()
                    )
                    // Redirect to the login page when not authenticated from the
                    // authorization endpoint
                    .exceptionHandling((exceptions) -> exceptions
                                    .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
//                            .defaultAuthenticationEntryPointFor(
//                                new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/google"),
//                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                            )
                    );

            return http.cors(Customizer.withDefaults()).build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
                throws Exception {
            http
                    .authorizeHttpRequests((authorize) -> authorize
                            .anyRequest().authenticated()
                    )
                    // Form login handles the redirect to the login page from the
                    // authorization server filter chain
                    .oauth2Login(Customizer.withDefaults());

            return http.cors(Customizer.withDefaults()).build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            config.addAllowedHeader("*");
            config.addAllowedMethod("*");
            config.addAllowedOrigin("http://localhost:3000");
            config.setAllowCredentials(true);
            source.registerCorsConfiguration("/**", config);
            return source;
        }



//        @Bean
//    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
//        return (authorities) -> {
//            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
//
//            authorities.forEach(authority -> {
//                System.out.println(authority.getAuthority());
//                mappedAuthorities.add(new SimpleGrantedAuthority(authority.getAuthority()));
//                if (OidcUserAuthority.class.isInstance(authority)) {
//                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;
//
//                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
//                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();
//                    System.out.println(userInfo.getClaims());
//
//                    // Map the claims found in idToken and/or userInfo
//                    // to one or more GrantedAuthority's and add it to mappedAuthorities
//
//                } else if (OAuth2UserAuthority.class.isInstance(authority)) {
//                    OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;
//
//                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();
//
//                    // Map the attributes found in userAttributes
//                    // to one or more GrantedAuthority's and add it to mappedAuthorities
//
//                }
//
//                //should we map authority and attributes from the token to the user here?
//            });
//
//            return mappedAuthorities;
//        };
//    }

//    @Bean
//    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> OAuth2TokenCustomizer() {
//        return context -> {
//            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
//
//            // Get existing scopes
//            Set<String> existingScopes = context.getClaims().build().getClaim(OAuth2ParameterNames.SCOPE);
//
//            // Create new set with existing and custom scopes
//            Set<String> customScopes = new HashSet<>(existingScopes);
//            customScopes.add("custom.scope"); // Add your custom scope
//
//            // Set the updated scopes
//            claims.claim(OAuth2ParameterNames.SCOPE, customScopes);
//        };
//    }



    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();

            if(principal.getPrincipal() instanceof OidcUser){

                OidcUser oidcUser = (OidcUser) principal.getPrincipal();

                //transfer oidcAuthorities to scopes
                Set<String> oidcAuthorities = oidcUser.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(scope -> scope.startsWith("SCOPE_"))
                        .map(scope -> scope.substring(6))
                        .collect(Collectors.toSet());
                context.getClaims().claim("scope", oidcAuthorities);

                System.out.println(oidcUser.getIdToken().getSubject());

                //Get other oidc claims
                List<String> otherOidcClaimsToCollect = Arrays.asList(
                        "email",
                        "name",
                        "given_name",
                        "family_name"
                );
                Map<String, Object> otherOidcClaims = otherOidcClaimsToCollect.stream()
                        .filter(claim -> oidcUser.getClaims().containsKey(claim))
                        .collect(Collectors.toMap(claim -> claim, claim -> oidcUser.getClaims().get(claim)));
                context.getClaims().claims(claims -> claims.putAll(otherOidcClaims));

            }

            //Add client credential authorized scope to token claims
            if(context.getAuthorizationGrantType() == AuthorizationGrantType.CLIENT_CREDENTIALS){
                context.getClaims().claim("scope", context.getAuthorizedScopes());
            }

                // Add mapped scopes to the token


            OAuth2AuthorizationGrantAuthenticationToken authorizationGrant =
                    context.getAuthorizationGrant();

            // Get request form parameters
            Map<String, Object> additionalParameters = authorizationGrant.getAdditionalParameters().entrySet().stream()
                    .filter(entry -> context.getClaims().build().getClaims().containsKey(entry.getKey())==false)
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            context.getClaims().claims(claimsMap -> claimsMap.putAll(additionalParameters));

        };
    }



//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails user = User.builder()
//                .username("user1")
//                .password("{noop}password")
////                .password(passwordEncoder().encode("password"))
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin1")
////                .password(passwordEncoder().encode("admin"))
//                .password("{noop}admin")
//                .roles("ADMIN", "USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }
//
//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//            List<ClientRegistration> providers = new ArrayList<>();
//            providers.add(this.googleClientRegistration());
//        return new InMemoryClientRegistrationRepository(providers);
//    }
//
//    private ClientRegistration googleClientRegistration() {
//        return ClientRegistration.withRegistrationId("google")
//                .clientId("google-client-id")
//                .clientSecret("google-client-secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
//                .scope("openid", "profile", "email", "address", "phone")
//                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
//                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
//                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
//                .userNameAttributeName(IdTokenClaimNames.SUB)
//                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
//                .clientName("Google")
//                .build();
//    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> registeredClients = new ArrayList<>();
        RegisteredClient frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientName("Sample Client")
                .clientId("public-client")
                .clientSecret(passwordEncoder().encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/callback")
                .redirectUri("http://localhost:3000/callback?provider=google")
                .redirectUri("http://localhost:3000/callback?provider=ciam")
                .redirectUri("http://localhost:3000/callback?provider=auth0")
                .tokenSettings(tokenSettings())
//                .scope(OidcScopes.OPENID)
//                .scope("read")
//                .scope("email")
//                .scope("profile")
//                .scope("openid")
//                .scope("https://api.thomsonreuters.com/auth/akkadia.akkadiax.auth.default")
//                .scope("https://api.thomsonreuters.com/auth/akkadia.akkadiax.auth.admin")
//                .clientSettings(ClientSettings.builder()
//                        .requireProofKey(true)  // Enable PKCE
//                        .requireAuthorizationConsent(true)
//                        .build())
                .build();

        RegisteredClient backendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oauth2-credential-flow-client")
//                .clientSecret("{noop}flow-secret")
                .clientSecret(passwordEncoder().encode("flow-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("https://api.thomsonreuters.com/auth/akkadia.akkadiax.auth.default")
                .scope("https://api.thomsonreuters.com/auth/akkadia.akkadiax.auth.admin")
                .scope("ROLE_SYSTEM_ADMIN")
                .tokenSettings(tokenSettings())
                .build();

        registeredClients.add(frontendClient);
        registeredClients.add(backendClient);

        return new InMemoryRegisteredClientRepository(registeredClients);
    }

    @Bean
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(12))
                .refreshTokenTimeToLive(Duration.ofDays(180))
                .reuseRefreshTokens(false)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
