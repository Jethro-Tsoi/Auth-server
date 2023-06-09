package com.regverse.auth.security;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.regverse.auth.userDetail.AppUserDetails;
import com.regverse.clients.country.CountryClient;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class TokenConfig {

    private final JWKSource<SecurityContext> jwkSource;
    private final CountryClient countryClient;

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer());
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public TokenSettings tokenSettings() {
        return TokenSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            OAuth2ClientAuthenticationToken principal = context.getPrincipal();
            AppUserDetails user = (AppUserDetails) principal.getDetails();
            Set<String> authorities = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            if (context.getTokenType().getValue().equals("access_token")) {
                String country = countryClient.findCountryNameByCountryId(user.getAppUser().getCountryId());
                context.getClaims()
                        .expiresAt(Instant.now().plus(1, ChronoUnit.DAYS))
                        .claim("country", country)
                        .claim("authorities", authorities)
                        .claim("user", user.getUsername());
            }
        };
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> auth2TokenCustomizer() {
//        return context -> {
//            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())){
//                Authentication authentication = context.getPrincipal();
//                if(!Objects.isNull(authentication)){
//                    Set<String> authorities = authentication.getAuthorities().stream()
//                            .map(GrantedAuthority::getAuthority)
//                            .collect(Collectors.toSet());
//                    context.getClaims()
//                            .claim("authorities", authorities);
//                }
//            }
//        };
//    }
}
