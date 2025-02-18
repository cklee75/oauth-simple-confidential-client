package dev.lydtech.security.simpleconfidentialclient.controllers;

import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;


import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuerUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    private final WebClient webClient;
    private final OAuth2AuthorizedClientService authorizedClientService;

    public ApiController(WebClient webClient, OAuth2AuthorizedClientService authorizedClientService) {
        this.webClient = webClient;
        this.authorizedClientService = authorizedClientService;
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

    @GetMapping("/refresh-token-raw")
    public ResponseEntity<String> refreshAccessTokenRaw(OAuth2AuthenticationToken authentication) {
        try {
            String tokenEndpoint = issuerUri + "/protocol/openid-connect/token";
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "keycloak", authentication.getName());
            String refreshToken = authorizedClient.getRefreshToken().getTokenValue();

            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "refresh_token");
            formData.add("client_id", clientId);
            formData.add("client_secret", clientSecret);
            formData.add("refresh_token", refreshToken);

            String response = webClient.post()
                    .uri(tokenEndpoint)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .bodyValue(formData)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, clientResponse ->
                            clientResponse.bodyToMono(String.class).flatMap(errorBody ->
                                    Mono.error(new RuntimeException("Token refresh failed: " + errorBody))
                            )
                    )
                    .bodyToMono(String.class)
                    .block();

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error refreshing access token: " + e.getMessage());
        }
    }

    @GetMapping(value = "/refresh-token", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> refreshAccessToken(OAuth2AuthenticationToken authentication) {
        try {
            String tokenEndpoint = issuerUri + "/protocol/openid-connect/token";
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "keycloak", authentication.getName());
            
            if (authorizedClient == null || authorizedClient.getRefreshToken() == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No valid refresh token found");
            }

            String refreshToken = authorizedClient.getRefreshToken().getTokenValue();

            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "refresh_token");
            formData.add("client_id", clientId);
            formData.add("client_secret", clientSecret);
            formData.add("refresh_token", refreshToken);

            // Make request to Keycloak
            String response = webClient.post()
                    .uri(tokenEndpoint)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .bodyValue(formData)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, clientResponse ->
                            clientResponse.bodyToMono(String.class).flatMap(errorBody ->
                                    Mono.error(new RuntimeException("Token refresh failed: " + errorBody))
                            )
                    )
                    .bodyToMono(String.class)
                    .block();

            // Parse response
            ObjectMapper mapper = new ObjectMapper();
            Map<String, String> tokens = mapper.readValue(response, Map.class);

            String accessToken = tokens.get("access_token");
            String idToken = tokens.get("id_token");
            String newRefreshToken = tokens.get("refresh_token");

            // Decode and format JWT
            String beautifiedAccessToken = decodeJWT(accessToken);
            String beautifiedIdToken = decodeJWT(idToken);
            String beautifiedRefreshToken = decodeJWT(newRefreshToken);

            return ResponseEntity.ok(
                    "Raw:\n" + response +
                    "\n\nNew Access Token:\n" + beautifiedAccessToken +
                    "\n\nNew ID Token:\n" + beautifiedIdToken +
                    "\n\nNew Refresh Token:\n" + beautifiedRefreshToken
            );
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error refreshing access token: " + e.getMessage());
        }
    }

    private String decodeJWT(String jwt) {
        try {
            if (jwt == null || !jwt.contains(".")) {
                return "Invalid JWT";
            }

            String[] parts = jwt.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

            ObjectMapper mapper = new ObjectMapper();
            Object json = mapper.readValue(payload, Object.class);

            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (Exception e) {
            return "Error decoding JWT: " + e.getMessage();
        }
    }

}
