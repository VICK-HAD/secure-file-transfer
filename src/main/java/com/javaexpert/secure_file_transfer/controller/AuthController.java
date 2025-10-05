package com.javaexpert.secure_file_transfer.controller;

import com.javaexpert.secure_file_transfer.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestParam String username, @RequestParam String password) {
        // We will now create this registerUser method in the UserService
        if (userService.registerUser(username, password)) {
            return ResponseEntity.ok("Registration successful!");
        } else {
            return ResponseEntity.badRequest().body("Username already exists.");
        }
    }
}