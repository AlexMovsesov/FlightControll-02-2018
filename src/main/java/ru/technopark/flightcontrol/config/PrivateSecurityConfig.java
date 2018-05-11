package ru.technopark.flightcontrol.config;

import com.allanditzel.springframework.security.web.csrf.CsrfTokenResponseHeaderBindingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import ru.technopark.flightcontrol.security.AuthenticationUserProvider;

@EnableWebSecurity
@Order(3)
public class PrivateSecurityConfig extends WebSecurityConfigurerAdapter {
    static final String SCOPE = "/api/user/**";
    //@todo: examine spring security for refactoring existing code.
    @Autowired
    private AuthenticationUserProvider authenticationUserProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.authenticationProvider(authenticationUserProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .antMatcher(SCOPE)
            .authorizeRequests()
                .antMatchers(HttpMethod.POST, SCOPE)
                .authenticated()
            .and()
                .addFilterAfter(new CsrfTokenResponseHeaderBindingFilter(), CsrfFilter.class);

    }
}
