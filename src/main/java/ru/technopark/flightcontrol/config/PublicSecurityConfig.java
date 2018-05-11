package ru.technopark.flightcontrol.config;

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
@Order(1)
public class PublicSecurityConfig extends WebSecurityConfigurerAdapter {
    static final String SCOPE = "/api/users/**";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .ignoringAntMatchers(SCOPE);
        http
            .antMatcher(SCOPE)
            .authorizeRequests()
                .anyRequest()
                .permitAll();
    }
}
