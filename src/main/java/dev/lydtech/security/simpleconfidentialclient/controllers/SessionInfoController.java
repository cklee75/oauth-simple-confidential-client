package dev.lydtech.security.simpleconfidentialclient.controllers;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/session")
public class SessionInfoController {

    @GetMapping("/timeout")
    public String getSessionTimeout(HttpSession session) {
        int timeout = session.getMaxInactiveInterval(); // Returns timeout in seconds
        return "Session Timeout: " + (timeout / 60) + " minutes";
    }
}
