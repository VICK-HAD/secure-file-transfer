package com.javaexpert.secure_file_transfer.config; // Or your config/security package

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // This allows the frontend (running on any origin) to call the backend.
                // For production, you would restrict the origin to your specific frontend domain.
                registry.addMapping("/api/**") // Apply to all endpoints under /api/
                        .allowedOrigins("*")   // Allow requests from any origin
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*");
            }
        };
    }
}