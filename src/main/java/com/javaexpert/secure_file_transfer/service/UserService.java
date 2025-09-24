package com.javaexpert.secure_file_transfer.service;

import com.javaexpert.secure_file_transfer.model.User;
import com.javaexpert.secure_file_transfer.repository.userRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private userRepository userRepository;

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean registerUser(String username, String password) {
        if (userRepository.existsByUsername(username)) {
            return false;
        }

        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(hashPassword(password));
        userRepository.save(user);
        return true;
    }

    public boolean loginUser(String username, String password) {
        String hashedPassword = hashPassword(password);
        Optional<User> userOptional = userRepository.findByUsernameAndPasswordHash(username, hashedPassword);
        return userOptional.isPresent();
    }
}