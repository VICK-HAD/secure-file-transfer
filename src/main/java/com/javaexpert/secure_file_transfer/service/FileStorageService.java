package com.javaexpert.secure_file_transfer.service;

import org.springframework.stereotype.Service;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.FileStore;

@Service
public class FileStorageService {

    private final Path rootLocation = Paths.get("uploads");

    public FileStorageService() {
        try {
            Files.createDirectories(rootLocation);
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize storage directory!", e);
        }
    }

    public boolean hasEnoughSpace(long fileSize) {
        try {
            FileStore store = Files.getFileStore(this.rootLocation);
            long usableSpace = store.getUsableSpace();
            return usableSpace > (fileSize + 25 * 1024 * 1024);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public void saveFile(byte[] fileBytes, String fileName) {
        try {
            if (fileName == null || fileName.contains("..")) {
                throw new RuntimeException("Cannot store file with relative path outside current directory: " + fileName);
            }

            Path destinationFile = this.rootLocation.resolve(Paths.get(fileName)).normalize();
            Files.write(destinationFile, fileBytes);

        } catch (IOException e) {
            throw new RuntimeException("Failed to store file: " + fileName, e);
        }
    }
}