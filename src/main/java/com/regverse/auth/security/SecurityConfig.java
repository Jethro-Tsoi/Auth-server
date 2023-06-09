package com.regverse.auth.security;

import com.regverse.auth.security.custom_password.CustomPasswordAuthenticationConverter;
import com.regverse.auth.security.custom_password.CustomPasswordAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.List;
import java.util.function.Consumer;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final UserDetailsService userDetailsService;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
//        http
//                // Redirect to the login page when not authenticated from the
//                // authorization endpoint
//                .exceptionHandling((exceptions) -> exceptions
//                        .authenticationEntryPoint(
//                                new LoginUrlAuthenticationEntryPoint("/login"))
//                )
//                // Accept access tokens for User Info and/or Client Registration
//                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//
//        return http.build();

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        return http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenRequestConverter(new CustomPasswordAuthenticationConverter())
                        .authenticationProvider(new CustomPasswordAuthenticationProvider(authorizationService(),
                                                                                        tokenGenerator,
                                                                                        userDetailsService))
                        .accessTokenRequestConverters(getConverters())
                        .authenticationProviders(getProviders()))
                .and()
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .build();
    }
    private Consumer<List<AuthenticationProvider>> getProviders() {
        return a -> a.forEach(System.out::println);
    }

    private Consumer<List<AuthenticationConverter>> getConverters() {
        return a -> a.forEach(System.out::println);
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
//        http
//                .formLogin()
//                .and()
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .authorizeHttpRequests()
//                .requestMatchers("/api/auth/login").anonymous()
//                .requestMatchers("/api/news/pre-authentication").anonymous()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .authenticationProvider(authenticationProvider)
////                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
//                .cors();
//        return http.build();
        http
                .csrf().disable()
                .formLogin()
                .and()
                .authorizeHttpRequests().anyRequest().authenticated();
        return http.build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .build();
    }
}

