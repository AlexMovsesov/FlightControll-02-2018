package ru.technopark.flightcontrol.config;

import com.allanditzel.springframework.security.web.csrf.CsrfTokenResponseHeaderBindingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import ru.technopark.flightcontrol.security.AuthenticationUserProvider;

@EnableWebSecurity
@Order(2)
public class EntryPointsSecurityConfig extends WebSecurityConfigurerAdapter {
    static final String SCOPE = "/api/entry/**";

    @Autowired
    private AuthenticationUserProvider authenticationUserProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.authenticationProvider(authenticationUserProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .ignoringAntMatchers(SCOPE);
        http
            .antMatcher(SCOPE)
            .authorizeRequests()
                .anyRequest()
                .permitAll()
            .and()
                .addFilterAfter(new CsrfTokenResponseHeaderBindingFilter(), CsrfFilter.class);
    }
}
