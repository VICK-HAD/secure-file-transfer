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
                // Integrate CORS configuration directly into the security chain
                .cors(Customizer.withDefaults())

                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Allow anyone to access the frontend, public key, AND storage check endpoints
                        .requestMatchers("/", "/index.html", "/script.js", "/style.css").permitAll()
                        .requestMatchers("/api/security/public-key", "/api/storage/check").permitAll()

                        // All other requests require the user to be authenticated
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.permitAll());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}