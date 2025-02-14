package dev.lydtech.security.simpleconfidentialclient.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;

import java.security.Principal;

@Controller
@Slf4j
@RequestMapping("/")
public class MyController {

    @GetMapping(path = "/")
    public String index(Model model) {
        // Need to look up principal here. By including it as a method param, Spring will redirect to login (which isn't required for this endpoint)
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof AuthenticatedPrincipal user) {
            model.addAttribute("username", user.getName());
        }
        return "public";
    }

    @GetMapping(path = "/users")
    public String users(Principal principal, Model model) {
        model.addAttribute("username", principal.getName());
        return "users";
    }

    @GetMapping(path = "/admin")
    public String admin(Principal principal, Model model) {
        model.addAttribute("username", principal.getName());
        return "admin";
    }

    private final OAuth2AuthorizedClientService authorizedClientService;

    public MyController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    // @GetMapping("/tokens")
    @RequestMapping(value="/tokens", method=RequestMethod.GET, produces="text/plain")
    @ResponseBody
    public String getTokens(Authentication authentication) {
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        String idToken = oidcUser.getIdToken().getTokenValue(); // Retrieve ID Token

        // Retrieve Access Token
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
            "keycloak", authentication.getName());
        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        String refreshToken = authorizedClient.getRefreshToken().getTokenValue();
        log.info("XXX ID Token: " + idToken + ", Access Token: " + accessToken + ", Refresh Token:" + refreshToken);
        return "ID Token: " + idToken + ", Access Token: " + accessToken + ", Refresh Token:" + refreshToken;
    }

    @RequestMapping(value="/userinfo", method=RequestMethod.GET, produces="text/plain")
    @ResponseBody
    public String userInfo(Authentication authentication) throws java.text.ParseException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();            
            String idToken = oidcUser.getIdToken().getTokenValue();

            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "keycloak", authentication.getName());
            String accessToken = authorizedClient.getAccessToken().getTokenValue();
            String refreshToken = authorizedClient.getRefreshToken().getTokenValue();

            log.info("[🔹 ID TOKEN] {}", decodeJWT(idToken));
            log.info("[🔹 ACCESS TOKEN] {}", decodeJWT(accessToken));
            log.info("[🔹 REFRESH TOKEN] {}", decodeJWT(refreshToken));

            log.info("[✅ USER INFO] {}", oidcUser.getAttributes());
            return oidcUser.getAttributes().toString();
        }
        return "No OAuth2 authentication found!";
    }

    private String decodeJWT(String token) {
            SignedJWT signedJWT;
            JWTClaimsSet claims;
            try {
                signedJWT = SignedJWT.parse(token);
                claims = signedJWT.getJWTClaimsSet();
                return String.format("""
                    {
                      "Issuer": "%s",
                      "Subject": "%s",
                      "Audience": "%s",
                      "Expiration Time": "%s",
                      "Issued At": "%s",
                      "User Info": "%s"
                    }
                    """,
                    claims.getIssuer(),
                    claims.getSubject(),
                    claims.getAudience(),
                    claims.getExpirationTime(),
                    claims.getIssueTime(),
                    claims.getClaims()
                );
    
            } catch (java.text.ParseException e) {
                log.error(token, e);
            }
        return token;

    }
}