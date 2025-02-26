package dev.lydtech.security.simpleconfidentialclient.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import dev.lydtech.security.simpleconfidentialclient.session.OIDCLoginSuccessHandler;
import lombok.extern.slf4j.Slf4j;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity
@Slf4j
class SecurityConfig {

    @Value("${domain-url}")
    private String domainUrl;

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuerUri;

    private final OIDCLoginSuccessHandler oidcLoginSuccessHandler;

    public SecurityConfig(OIDCLoginSuccessHandler oidcLoginSuccessHandler) {
        this.oidcLoginSuccessHandler = oidcLoginSuccessHandler;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(issuerUri + "/protocol/openid-connect/certs").build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorise ->
                authorise
                        .requestMatchers("/")
                        .permitAll()
                        .requestMatchers("/", "/logout/backchannel")
                        .permitAll()
                        .requestMatchers("/admin*")
                        .hasRole("admin")
                        .requestMatchers("/users*")
                        .hasAnyRole("user", "admin", "USER", "ADMIN")
                        .requestMatchers("/tokens*")
                        .hasAnyRole("user", "admin", "USER", "ADMIN")
                        .anyRequest()
                        .authenticated())
            .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/logout/backchannel"));
        http.oauth2Login(oauth2 -> oauth2
                    .successHandler(oidcLoginSuccessHandler))
                .logout(logout ->
                        logout
                        .logoutSuccessUrl(issuerUri + "/protocol/openid-connect/logout?redirect_uri=" + domainUrl)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID"));
        http
            .sessionManagement(session -> session
                .sessionFixation(sessionFixation -> sessionFixation.none()));

        return http.build();
    }


    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcUserAuthority) {

                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                    // Map the claims found in idToken and/or userInfo
                    // to one or more GrantedAuthority's and add it to mappedAuthorities
                    // NOTES: MyOne SSO does not store realm_access under User Info
                    Map<String, Object> realmAccess = userInfo.getClaim("realm_access");
                    Collection<String> realmRoles;
                    if (realmAccess != null
                            && (realmRoles = (Collection<String>) realmAccess.get("roles")) != null) {
                        realmRoles
                                .forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
                            mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                    }

                }

                
                if (authority instanceof SimpleGrantedAuthority simpleGrantedAuthority) {
                    log.info("Role: " + simpleGrantedAuthority.getAuthority());
                    // FIXME: Temporary add ROLE_USER to any authenticated users
                    mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                }
            });

            return mappedAuthorities;
        };
    }
}