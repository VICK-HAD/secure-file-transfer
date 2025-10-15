package com.javaexpert.secure_file_transfer.service;

import com.javaexpert.secure_file_transfer.model.User;
import com.javaexpert.secure_file_transfer.repository.userRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final userRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(userRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPassword())
                .roles("USER")
                .build();
    }

    public boolean registerUser(String username, String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            return false;
        }

        User newUser = new User();
        newUser.setUsername(username);

        newUser.setPassword(passwordEncoder.encode(password));

        userRepository.save(newUser);

        return true;
    }
}