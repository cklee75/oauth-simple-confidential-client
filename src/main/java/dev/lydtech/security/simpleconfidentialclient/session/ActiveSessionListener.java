package dev.lydtech.security.simpleconfidentialclient.session;

import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

@Component
// @WebListener
public class ActiveSessionListener implements HttpSessionListener {
    /* private static final Map<String, HttpSession> sessionMap = new ConcurrentHashMap<>();

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        sessionMap.put(event.getSession().getId(), event.getSession());
        System.out.println("Session Created: " + event.getSession().getId());
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        sessionMap.remove(event.getSession().getId());
        System.out.println("Session Destroyed: " + event.getSession().getId());
    }

    public static HttpSession getSession(String sessionId) {
        return sessionMap.get(sessionId);
    } */

    private static final ConcurrentHashMap<String, HttpSession> activeSessions = new ConcurrentHashMap<>();

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        activeSessions.put(session.getId(), session);
        System.out.println("✅ Session Created: " + session.getId());
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        activeSessions.remove(event.getSession().getId());
        System.out.println("❌ Session Destroyed: " + event.getSession().getId());
    }

    public static HttpSession getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }

    public static Set<String> getActiveSessionIds() {
        return activeSessions.keySet();
    }

}
