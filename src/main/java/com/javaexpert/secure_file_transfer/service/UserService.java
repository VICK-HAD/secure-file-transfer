package com.javaexpert.secure_file_transfer.service;

import com.javaexpert.secure_file_transfer.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final userRepository userRepository;

    @Autowired
    public UserService(userRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Find the user in the database.
        com.javaexpert.secure_file_transfer.model.User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // Convert your User object into a Spring Security UserDetails object.
        return User.withUsername(user.getUsername())
                .password(user.getPassword())
                .roles("USER") // You can define roles here
                .build();
    }
}