package com.security.jwt.config;


import com.security.jwt.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTOauthFilter jwtOauthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        System.out.println("In SecurityConfig.securityFilterChain()");

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((requests) -> {
                                               requests
                                                       .requestMatchers("/api/auth/**")
                                                       .permitAll();
                })
                .authorizeHttpRequests((requests) -> {
                                               requests
                                                       .requestMatchers("/api/test/admin/**")
                                                       .hasAuthority(Role.ADMIN.name())
                                               ;
                })
                .authorizeHttpRequests((requests) -> {
                    requests
                            .requestMatchers("/api/test/user/**")
                            .hasAuthority(Role.USER.name())
                    ;
                })
                .sessionManagement(
                        (session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtOauthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
