package dev.lydtech.security.simpleconfidentialclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class LoggingRequestInterceptor implements ClientHttpRequestInterceptor {
    private static final Logger logger = LoggerFactory.getLogger(LoggingRequestInterceptor.class);

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        logger.info("🌍 [Interceptor] Request: {} {}", request.getMethod(), request.getURI());
        logger.info("📝 Headers: {}", request.getHeaders());
        logger.info("📤 Body: {}", new String(body, StandardCharsets.UTF_8));

        ClientHttpResponse response = execution.execute(request, body);

        logger.info("✅ [Interceptor] Response Status: {}", response.getStatusCode());
        return response;
    }
}
