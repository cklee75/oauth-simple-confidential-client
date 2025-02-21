package dev.lydtech.security.simpleconfidentialclient.controllers;

import java.util.Map;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import dev.lydtech.security.simpleconfidentialclient.session.ActiveSessionListener;
import dev.lydtech.security.simpleconfidentialclient.session.OIDCLoginSuccessHandler;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/logout")
public class KeycloakBackChannelLogoutController {

    private final JwtDecoder jwtDecoder;

    public KeycloakBackChannelLogoutController(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @PostMapping("/backchannel")
    public void backChannelLogout(@RequestParam("logout_token") String logoutToken, HttpSession session, HttpServletRequest request, HttpServletResponse response) {
        try {
            // 1️⃣ Decode and Verify Logout Token
            Jwt jwt = jwtDecoder.decode(logoutToken);
            String keycloakSessionId = jwt.getClaimAsString("sid");  // Session ID from logout token
            System.out.println("Received back-channel logout for keycloak session: " + keycloakSessionId);

            // Find and invalidate corresponding HttpSession
            String httpSessionId = OIDCLoginSuccessHandler.getHttpSessionId(keycloakSessionId);

            // Debug: Print all tracked sessions
            System.out.println("All active session IDs: " + ActiveSessionListener.getActiveSessionIds());

            if (httpSessionId != null) {
                System.out.println("Active session found for Keycloak SID: " + keycloakSessionId + " HttpSession Id: " + httpSessionId);
                HttpSession foundSession = ActiveSessionListener.getSession(httpSessionId);
                if (foundSession != null) {
                    foundSession.invalidate();
                    System.out.println("Session invalidated successfully: " + httpSessionId);
                } else {
                    System.out.println("Found session is null");
                }
            } else {
                System.out.println("No active session found for Keycloak SID: " + keycloakSessionId);
            }

            // 2️⃣ Invalidate Session
            session.invalidate();  // Clears session data
            SecurityContextHolder.clearContext();  // Clears security context

            System.out.println("Session invalidated successfully.");

            // Invalidate the HTTP session
            request.getSession().invalidate();

            // Remove JSESSIONID cookie from response
            removeCookie(response, "JSESSIONID");
        } catch (Exception e) {
            System.err.println("Invalid logout token: " + e.getMessage());
        }
    }

    private void removeCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0); // Expire the cookie
        response.addCookie(cookie);
    }

    @PostMapping(value = "/backchannel-wrong", consumes = {"application/json", "application/x-www-form-urlencoded"})
    public String backChannelLogout(@RequestParam Map<String, String> formParams, @RequestBody(required = false) Map<String, Object> jsonBody) {
        String keycloakSessionId = null;

        // Check if Keycloak sent JSON
        if (jsonBody != null && jsonBody.containsKey("sid")) {
            keycloakSessionId = (String) jsonBody.get("sid");
        }
        // Check if Keycloak sent form data
        else if (formParams.containsKey("sid")) {
            keycloakSessionId = formParams.get("sid");
        }

        if (keycloakSessionId == null) {
            return "No session ID found in request.";
        }

        System.out.println("Received back-channel logout for session: " + keycloakSessionId);

        // Find and invalidate corresponding HttpSession
        String httpSessionId = OIDCLoginSuccessHandler.getHttpSessionId(keycloakSessionId);
        if (httpSessionId != null) {
            HttpSession session = ActiveSessionListener.getSession(httpSessionId);
            if (session != null) {
                session.invalidate();
                System.out.println("Session invalidated successfully: " + httpSessionId);
            }
        } else {
            System.out.println("No active session found for Keycloak SID: " + keycloakSessionId);
        }

        return "Back-channel logout successful";
    }
}

