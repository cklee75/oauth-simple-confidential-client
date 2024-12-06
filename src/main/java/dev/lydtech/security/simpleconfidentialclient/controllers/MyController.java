package dev.lydtech.security.simpleconfidentialclient.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

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
        System.out.println("XXX ID Token: " + idToken + ", Access Token: " + accessToken);
        return "ID Token: " + idToken + ", Access Token: " + accessToken;
    }
}