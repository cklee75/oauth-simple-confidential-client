package dev.lydtech.security.simpleconfidentialclient.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;
import dev.lydtech.security.simpleconfidentialclient.LoggingRequestInterceptor;
import dev.lydtech.security.simpleconfidentialclient.session.OIDCLoginSuccessHandler;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@Slf4j
class SecurityConfig {

    private final OIDCLoginSuccessHandler oidcLoginSuccessHandler;

    public SecurityConfig(OIDCLoginSuccessHandler oidcLoginSuccessHandler) {
        this.oidcLoginSuccessHandler = oidcLoginSuccessHandler;
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        // successHandler.setPostLogoutRedirectUri(URI.create("http://localhost:8082").toString());
        successHandler.setPostLogoutRedirectUri(URI.create("https://prawn-humble-mackerel.ngrok-free.app").toString());
        return successHandler;
    }
        @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri("https://app.please-open.it/auth/realms/ee1afd72-71a9-49ad-a975-54ed46cc56a3/protocol/openid-connect/certs").build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler, OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient) throws Exception {
        http
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin()) // Allow same-origin iframes
                .contentSecurityPolicy(csp -> csp.policyDirectives("frame-src 'self' https://app.please-open.it http://localhost:8082 https://prawn-humble-mackerel.ngrok-free.app;"))
                .contentSecurityPolicy(csp -> csp.policyDirectives("frame-ancestors 'self' https://app.please-open.it;"))

            );
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
                        .logoutSuccessHandler(oidcLogoutSuccessHandler)
                        .logoutSuccessUrl("https://app.please-open.it/auth/realms/ee1afd72-71a9-49ad-a975-54ed46cc56a3/protocol/openid-connect/logout?redirect_uri=http://localhost:8082")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID"));
        http
            .sessionManagement(session -> session
                .sessionFixation(sessionFixation -> sessionFixation.none()));

        return http.build();
    }

    @Bean
    public RestTemplate restTemplate() {

        RestTemplate restTemplate = new RestTemplate(new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory()));
        List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
        interceptors.add(new LoggingRequestInterceptor());
        restTemplate.setInterceptors(interceptors);

        return restTemplate;
    }

    @Bean
    public DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
        client.setRestOperations(restTemplate()); // ✅ Use custom RestTemplate
        return client;
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