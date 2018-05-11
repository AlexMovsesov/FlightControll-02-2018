package ru.technopark.flightcontrol.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import ru.technopark.flightcontrol.dao.UsersManager;
import ru.technopark.flightcontrol.models.User;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public final class UserLogoutHandler implements LogoutHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserLogoutHandler.class);
    private UsersManager manager;

    UserLogoutHandler(UsersManager manager) {
        this.manager = manager;
    }

    private User prepareEnviron(HttpSession session) {
        final Number userId = (Number) session.getAttribute("userId");
        return manager.getUser(userId);
    }
    /* (non-Javadoc)
     * @see org.springframework.security.web.authentication.logout.LogoutHandler#
     * logout(
     *  javax.servlet.http.HttpServletRequest,
     *  javax.servlet.http.HttpServletResponse,
     *  org.springframework.security.core.Authentication
     *  )
     */

    @Override
    public void logout(HttpServletRequest req, HttpServletResponse res,
                       Authentication authentication) {
        final HttpSession session = req.getSession();
        session.invalidate();
        final User curUser = prepareEnviron(session);
        if (curUser == null) {
            return;
        }
        session.removeAttribute("userId");
        authentication.setAuthenticated(false);
    }

}