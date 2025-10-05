package com.javaexpert.secure_file_transfer.controller;

import com.javaexpert.secure_file_transfer.service.FileStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/storage")
public class StorageController {

    private final FileStorageService fileStorageService;

    @Autowired
    public StorageController(FileStorageService fileStorageService) {
        this.fileStorageService = fileStorageService;
    }

    @GetMapping("/check")
    public ResponseEntity<Map<String, Boolean>> checkStorage(@RequestParam long fileSize) {
        boolean hasSpace = fileStorageService.hasEnoughSpace(fileSize);
        return ResponseEntity.ok(Map.of("hasEnoughSpace", hasSpace));
    }
}