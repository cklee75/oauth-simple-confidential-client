package dev.lydtech.security.simpleconfidentialclient;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class RequestResponseLoggingFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(RequestResponseLoggingFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        logger.info("Incoming Request: [{}] {}", req.getMethod(), req.getRequestURI());
        req.getHeaderNames().asIterator().forEachRemaining(header ->
                logger.info("Header: {} = {}", header, req.getHeader(header))
        );

        chain.doFilter(request, response);

        logger.info("Outgoing Response: {} {}", res.getStatus(), res.getContentType());
    }
}
