package com.javaexpert.secure_file_transfer.service;

import com.javaexpert.secure_file_transfer.model.User; // Import your User model
import com.javaexpert.secure_file_transfer.repository.userRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder; // Import PasswordEncoder
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final userRepository userRepository;
    private final PasswordEncoder passwordEncoder; // Inject the password encoder

    @Autowired
    public UserService(userRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // This is the login logic that Spring Security uses. It's already correct.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPassword())
                .roles("USER")
                .build();
    }

    /**
     * This is the new registration method.
     */
    public boolean registerUser(String username, String password) {
        // 1. Check if the username is already taken.
        if (userRepository.findByUsername(username).isPresent()) {
            return false; // Registration failed
        }

        // 2. Create a new User object.
        User newUser = new User();
        newUser.setUsername(username);

        // 3. Hash the password before saving it.
        newUser.setPassword(passwordEncoder.encode(password));

        // 4. Save the new user to the database.
        userRepository.save(newUser);

        return true; // Registration successful
    }
}