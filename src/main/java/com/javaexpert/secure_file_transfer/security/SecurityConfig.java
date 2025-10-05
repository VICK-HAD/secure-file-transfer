// Will contain TLS/HTTPS configuration.
package com.javaexpert.secure_file_transfer.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * This bean defines the central security rules for the application.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF protection. While important for browser-based forms, it can be
                // simplified for this type of API-driven, single-page application.
                .csrf(csrf -> csrf.disable())

                // Define authorization rules for HTTP requests.
                .authorizeHttpRequests(auth -> auth
                        // Allow anyone to access the frontend files and the public key endpoint.
                        .requestMatchers("/", "/index.html", "/script.js", "/style.css").permitAll()
                        .requestMatchers("/api/security/public-key").permitAll()

                        // All other requests (including our file upload) require the user to be authenticated.
                        .anyRequest().authenticated()
                )

                // Enable a default form-based login page provided by Spring Security.
                .formLogin(form -> form.permitAll());

        return http.build();
    }

    /**
     * This bean creates a simple in-memory user for testing purposes.
     * You would replace this with a database-backed user service in a real application.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // Create a user with the username "user", password "password", and role "USER".
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        // Return the user manager.
        return new InMemoryUserDetailsManager(user);
    }
}