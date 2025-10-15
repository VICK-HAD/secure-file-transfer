package com.javaexpert.secure_file_transfer.controller;

import com.javaexpert.secure_file_transfer.model.ApiResponse;
import com.javaexpert.secure_file_transfer.service.CryptoService;
import com.javaexpert.secure_file_transfer.service.FileStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class FileUploadController {

    private final CryptoService cryptoService;
    private final FileStorageService fileStorageService;

    @Autowired
    public FileUploadController(CryptoService cryptoService, FileStorageService fileStorageService) {
        this.cryptoService = cryptoService;
        this.fileStorageService = fileStorageService;
    }

    @GetMapping("/security/public-key")
    public ResponseEntity<Map<String, String>> getPublicKey() {
        String base64PublicKey = cryptoService.getPublicKeyAsBase64();
        return ResponseEntity.ok(Map.of("publicKey", base64PublicKey));
    }

    @PostMapping("/files/upload")
    public ResponseEntity<ApiResponse> uploadFile(
            @RequestParam("file") MultipartFile encryptedFile,
            @RequestParam("key") MultipartFile encryptedKey,
            @RequestParam("hash") String originalHashHex) {

        try {
            byte[] encryptedKeyBytes = encryptedKey.getBytes();
            SecretKey aesKey = cryptoService.decryptAesKey(encryptedKeyBytes);

            byte[] encryptedFileBytes = encryptedFile.getBytes();
            byte[] decryptedFileBytes = cryptoService.decryptFile(encryptedFileBytes, aesKey);

            boolean isHashValid = cryptoService.verifyHash(decryptedFileBytes, originalHashHex);
            if (!isHashValid) {
                return new ResponseEntity<>(new ApiResponse("Integrity check failed. File is compromised."), HttpStatus.BAD_REQUEST);
            }

            fileStorageService.saveFile(decryptedFileBytes, encryptedFile.getOriginalFilename());

            return new ResponseEntity<>(new ApiResponse("File uploaded, decrypted, and verified successfully!"), HttpStatus.OK);

        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(new ApiResponse("An error occurred during the cryptographic process: " + e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}