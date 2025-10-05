package com.javaexpert.secure_file_transfer.repository;

import com.javaexpert.secure_file_transfer.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface userRepository extends JpaRepository<User, Long> {
    // This method will find a user by their username. Spring creates the implementation for you.
    Optional<User> findByUsername(String username);
}