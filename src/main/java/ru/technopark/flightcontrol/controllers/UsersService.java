package ru.technopark.flightcontrol.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.technopark.flightcontrol.dao.UsersManager;
import ru.technopark.flightcontrol.models.User;
import ru.technopark.flightcontrol.validators.Validator;
import ru.technopark.flightcontrol.wrappers.*;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.HashMap;

@CrossOrigin(origins = {
        "127.0.0.1",
        "https://flightcontrolfrontend.herokuapp.com"
}, allowCredentials = "true", maxAge = 3600)
@RestController
@MultipartConfig
@RequestMapping(value = "/api/user")
public class UsersService {
    private static final Logger LOGGER = LoggerFactory.getLogger(UsersService.class);
    private UsersManager manager;

    UsersService(UsersManager manager) {
        this.manager = manager;
    }

    private User prepareEnviron(HttpSession session) {
        final Number userId = (Number) session.getAttribute("userId");
        return manager.getUser(userId);
    }

    @PostMapping(value = "/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
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
                session.setAttribute("userId", curUser.getId());
            }
        } catch (RequestParamsException exception) {
            return ResponseEntity.badRequest().body(exception.getFieldErrors());
        }
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/get", consumes = "application/json")
    public ResponseEntity getUser(HttpSession session) {
        final User curUser = prepareEnviron(session);
        if (curUser == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(curUser);
    }

    @GetMapping(value = "/logged", consumes = "application/json")
    public ResponseEntity isLogged(HttpSession session) {
        final User curUser = prepareEnviron(session);
        return curUser == null
                ? ResponseEntity.status(HttpStatus.FORBIDDEN).build()
                : ResponseEntity.ok().build();
    }


    @PostMapping(value = "/authenticate", consumes = "application/json")
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
            if (isValid) {
                session.setAttribute("userId", user.getId());
            }
        } catch (RequestParamsException exception) {
            return ResponseEntity.badRequest().body(exception.getFieldErrors());
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping(value = "/change", consumes = "application/json")
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

    @PostMapping(value = "/logout", consumes = "application/json")
    public ResponseEntity<?> logout(HttpSession session) {
        final User curUser = prepareEnviron(session);
        if (curUser == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        session.removeAttribute("userId");
        return  ResponseEntity.ok().build();
    }

    @PostMapping(value = "/leaders", consumes = "application/json")
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



}

