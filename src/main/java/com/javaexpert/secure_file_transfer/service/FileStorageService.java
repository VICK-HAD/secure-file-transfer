// Logic for saving/managing files.
package com.javaexpert.secure_file_transfer.service;

import org.springframework.stereotype.Service;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class FileStorageService {

    // This defines the root directory where uploaded files will be stored.
    // In this case, it will be a folder named "uploads" in your project's root directory.
    private final Path rootLocation = Paths.get("uploads");

    /**
     * This constructor runs when the service is created.
     * It creates the "uploads" directory if it doesn't already exist.
     */
    public FileStorageService() {
        try {
            Files.createDirectories(rootLocation);
        } catch (IOException e) {
            // If the directory can't be created, the application can't function.
            throw new RuntimeException("Could not initialize storage directory!", e);
        }
    }

    /**
     * This is the main method that saves the file.
     * It takes the decrypted file data (as a byte array) and the original filename.
     * @param fileBytes The raw bytes of the decrypted file.
     * @param fileName The original name of the file.
     */
    public void saveFile(byte[] fileBytes, String fileName) {
        try {
            // Basic security check to prevent path traversal attacks (e.g., saving files outside the intended directory).
            if (fileName == null || fileName.contains("..")) {
                throw new RuntimeException("Cannot store file with relative path outside current directory: " + fileName);
            }

            // Determine the full path for the new file and write the bytes to it.
            Path destinationFile = this.rootLocation.resolve(Paths.get(fileName)).normalize();
            Files.write(destinationFile, fileBytes);

        } catch (IOException e) {
            // If anything goes wrong during the file write, throw an exception.
            throw new RuntimeException("Failed to store file: " + fileName, e);
        }
    }
}