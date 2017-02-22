package me.learning.config;

import me.learning.security.JwtTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration that will handles all incoming traffic to the service
 *
 * @author WolfAlexander nikal@kth.se
 */

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebConfig extends WebSecurityConfigurerAdapter {

    /**
     * @return new filter that handles JWT tokens
     */
    @Bean
    public JwtTokenFilter filter(){
        return new JwtTokenFilter();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                    .antMatchers("/" ).permitAll()
                    .antMatchers("/info").authenticated()
                    .anyRequest().authenticated();

        http.addFilterBefore(filter(), UsernamePasswordAuthenticationFilter.class);
        http.headers().cacheControl();
    }
}
