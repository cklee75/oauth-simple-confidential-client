package dev.lydtech.security.simpleconfidentialclient.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class OIDCLoginSuccessHandler implements AuthenticationSuccessHandler {
    private static final Map<String, String> sessionMap = new ConcurrentHashMap<>();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response,
                                        org.springframework.security.core.Authentication authentication)
            throws IOException {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();
        
        String keycloakSessionId = oidcUser.getClaimAsString("sid");
        String httpSessionId = request.getSession().getId();

        if (keycloakSessionId != null) {
            sessionMap.put(keycloakSessionId, httpSessionId);
            System.out.println("Mapped Keycloak SID " + keycloakSessionId + " to HTTP session " + httpSessionId);
        }

        response.sendRedirect("/");
    }

    public static String getHttpSessionId(String keycloakSessionId) {
        return sessionMap.get(keycloakSessionId);
    }
}
