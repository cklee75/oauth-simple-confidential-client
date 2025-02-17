package dev.lydtech.security.simpleconfidentialclient.controllers;

import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuerUri;

    private final WebClient webClient;

    public ApiController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping("/userinfo")
    public String callExternalApi(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient) {
        try {
            return webClient.get()
                    .uri(issuerUri + "/protocol/openid-connect/userinfo")
                    .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, response ->
                            response.bodyToMono(String.class)
                                    .defaultIfEmpty("No error body")
                                    .flatMap(errorBody -> {
                                        return Mono.error(new RuntimeException("Request failed with status: " 
                                                + response.statusCode() + " and body: " + errorBody));
                                    })
                    )
                    .bodyToMono(String.class)
                    .doOnError(error -> System.err.println("WebClient Error: " + error.getMessage())) // Log error
                    .onErrorReturn("Error: Unable to fetch user info") // Return default value instead of crashing
                    .block();
        } catch (Exception e) {
            e.printStackTrace(); // Print stack trace for debugging
            return "Error: Exception occurred while calling userinfo API";
        }
    }
    
}
