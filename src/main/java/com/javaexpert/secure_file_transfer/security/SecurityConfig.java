package com.javaexpert.secure_file_transfer.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable()) // Disable CSRF
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/index.html",
                                "/script.js",
                                "/style.css",
                                "/api/security/public-key",
                                "/api/storage/check",
                                "/api/auth/register" // Also permit registration
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                // Explicitly configure form login
                .formLogin(form -> form
                        .loginProcessingUrl("/login") // The URL to submit the login form to
                        .defaultSuccessUrl("/", true) // Redirect to the main page on success
                        .permitAll()
                )
                // Explicitly configure logout
                .logout(logout -> logout
                        .logoutUrl("/logout") // The URL to trigger logout
                        .deleteCookies("JSESSIONID") // Invalidate the session cookie
                        .logoutSuccessUrl("/") // Redirect to the main page after logout
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}