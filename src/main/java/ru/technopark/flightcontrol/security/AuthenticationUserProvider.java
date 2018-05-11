package ru.technopark.flightcontrol.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import ru.technopark.flightcontrol.dao.UsersManager;
import ru.technopark.flightcontrol.models.User;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;

@Component
public class AuthenticationUserProvider implements AuthenticationProvider {
    private UsersManager manager;

    AuthenticationUserProvider(UsersManager manager) {
        this.manager = manager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String email = authentication.getName();
        final String password = authentication.getCredentials().toString();
        if (authentication.isAuthenticated()) {
            return authentication;
        }
        final User user = manager.getByEmail(email);
        if (user == null) {
            return authentication;
        }
        manager.authenticate(user, password);
        return new UsernamePasswordAuthenticationToken(email, password, new ArrayList<>());
    }

    public void assign(Authentication authentication, HttpSession session, User user) {
        final SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        session.setAttribute("userId", user.getId());
    }

    @Override
    public boolean supports(Class<?> authenticator) {
        return authenticator.equals(UsernamePasswordAuthenticationToken.class);
    }
}
