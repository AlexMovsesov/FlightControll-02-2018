package ru.technopark.flightcontrol.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.technopark.flightcontrol.dao.UsersManager;
import ru.technopark.flightcontrol.models.User;
import ru.technopark.flightcontrol.security.AuthenticationUserProvider;
import ru.technopark.flightcontrol.validators.Validator;
import ru.technopark.flightcontrol.wrappers.*;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.HashMap;

@CrossOrigin(origins = {
        "https://flightcontrolfrontend.herokuapp.com"
        },
        allowCredentials = "true",
        maxAge = 3600,
        allowedHeaders = {"Content-Type", "X-CSRF-TOKEN"},
        exposedHeaders = {"X-CSRF-TOKEN"}
    )
@RestController
@MultipartConfig
@RequestMapping(value = "/api", produces = MediaType.APPLICATION_JSON_VALUE)
public class UsersService {
    private static final Logger LOGGER = LoggerFactory.getLogger(UsersService.class);
    private UsersManager manager;
    private AuthenticationUserProvider authManager;

    UsersService(UsersManager manager, AuthenticationUserProvider authenticationManager) {
        this.manager = manager;
        this.authManager = authenticationManager;
        manager.createUser(new RegisterWrapper("vasya1", "vasya1@ya.ru", "123321", "123321", null), LOGGER);
        manager.createUser(new RegisterWrapper("vasya2", "vasya2@ya.ru", "123321", "123321", null), LOGGER);
        manager.createUser(new RegisterWrapper("vasya3", "vasya3@ya.ru", "123321", "123321", null), LOGGER);
    }

    private User prepareEnviron(HttpSession session) {
        final Number userId = (Number) session.getAttribute("userId");
        return manager.getUser(userId);
    }

    @GetMapping(value = "/users/logged", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity isLogged(HttpSession session) {
         final User curUser = prepareEnviron(session);
        return curUser == null
                ? ResponseEntity.status(HttpStatus.FORBIDDEN).build()
                : ResponseEntity.ok().build();
    }


    @PostMapping(value = "/users/leaders", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity leaders(HttpSession session, @RequestBody PaginateWrapper request) {
        final ArrayList<User> leaders;
        final HashMap<String, Object> response = new HashMap<>();
        try {
            Validator.validate(request);
            leaders = manager.getLeaders(request.getPage(), request.getSize());
            response.put("leaders", leaders);
            response.put("count", manager.getLeadersCount());
        } catch (RequestParamsException exception) {
            return ResponseEntity.badRequest().body(exception.getFieldErrors());
        }
        return  ResponseEntity.ok(response);
    }

    @PostMapping(value = "/entry/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity registerUser(HttpSession session,
                                       @RequestParam("username") String name,
                                       @RequestParam("email") String email,
                                       @RequestParam("password") String password,
                                       @RequestParam("password_repeat") String passwordRepeat,
                                       @RequestParam(value = "img", required = false) MultipartFile file) {
        final RegisterWrapper request = new RegisterWrapper(name, email, password, passwordRepeat, file);
        User curUser = prepareEnviron(session);
        if (curUser != null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        try {
            Validator.validate(request);
            curUser = manager.createUser(request, LOGGER);
            if (curUser == null) {
                return ResponseEntity.badRequest().body(new FieldsError("user", " is used"));
            } else {
                final UsernamePasswordAuthenticationToken token =
                        new UsernamePasswordAuthenticationToken(
                                email,
                                password,
                                curUser.getAuthorities()
                        );
                final Authentication authentication = authManager.authenticate(token);
                authManager.assign(authentication, session, curUser);
            }
        } catch (RequestParamsException exception) {
            return ResponseEntity.badRequest().body(exception.getFieldErrors());
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping(value = "/entry/authenticate", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity authUser(HttpSession session, @RequestBody AuthWrapper request) {
        final User curUser = prepareEnviron(session);
        if (curUser != null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        try {
            Validator.validate(request);
            final User user = manager.getByEmail(request.getEmail());
            if (user == null) {
                return ResponseEntity.badRequest().body("Unsaved user");
            }
            final boolean isValid = manager.authenticate(user, request.getPass());
            if (!isValid) {
                throw new RequestParamsException("user", "is not assignable");
            }
            final UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPass(),
                            user.getAuthorities()
                    );
            final Authentication authentication = authManager.authenticate(token);
            authManager.assign(authentication, session, user);
            return ResponseEntity.ok().build();
        } catch (RequestParamsException exception) {
            return ResponseEntity.badRequest().body(exception.getFieldErrors());
        }
    }

    @GetMapping(value = "/user/get", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity getUser(HttpSession session) {
        final User curUser = prepareEnviron(session);
        if (curUser == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(curUser);
    }





    @PostMapping(value = "/user/change", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity changeUser(HttpSession session,
                                     @RequestParam(value = "username") String name,
                                     @RequestParam(value = "email") String email,
                                     @RequestParam(value = "password") String password,
                                     @RequestParam(value = "password_repeat") String passwordRepeat,
                                     @RequestParam(value = "img", required = false) MultipartFile file) {
        final RegisterWrapper request = new RegisterWrapper(name, email, password, passwordRepeat, file);
        final User curUser = prepareEnviron(session);
        if (curUser == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        manager.changeUser(curUser, request);
        return ResponseEntity.ok().build();
    }

    @PostMapping(value = "/user/logout", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> logout(HttpSession session) {
        final User curUser = prepareEnviron(session);
        if (curUser == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        session.invalidate();
        return  ResponseEntity.ok().build();
    }


}

