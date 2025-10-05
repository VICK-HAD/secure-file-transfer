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

    /**
     * This new endpoint provides the server's public RSA key to the client.
     * The client will use this to encrypt the AES session key.
     */
    @GetMapping("/security/public-key")
    public ResponseEntity<Map<String, String>> getPublicKey() {
        String base64PublicKey = cryptoService.getPublicKeyAsBase64();
        // We return the key in a simple JSON object for the JavaScript to easily parse.
        return ResponseEntity.ok(Map.of("publicKey", base64PublicKey));
    }

    /**
     * This is the main file upload endpoint. It now expects three parts:
     * 1. The encrypted file.
     * 2. The encrypted AES key.
     * 3. The original file's SHA-256 hash.
     */
    @PostMapping("/files/upload")
    public ResponseEntity<ApiResponse> uploadFile(
            @RequestParam("file") MultipartFile encryptedFile,
            @RequestParam("key") MultipartFile encryptedKey,
            @RequestParam("hash") String originalHashHex) {

        try {
            // Step 1: Decrypt the AES session key using the server's private RSA key.
            byte[] encryptedKeyBytes = encryptedKey.getBytes();
            SecretKey aesKey = cryptoService.decryptAesKey(encryptedKeyBytes);

            // Step 2: Decrypt the file content using the decrypted AES key.
            byte[] encryptedFileBytes = encryptedFile.getBytes();
            byte[] decryptedFileBytes = cryptoService.decryptFile(encryptedFileBytes, aesKey);

            // Step 3: Verify the integrity of the decrypted file by comparing hashes.
            boolean isHashValid = cryptoService.verifyHash(decryptedFileBytes, originalHashHex);
            if (!isHashValid) {
                // If hashes don't match, the file is corrupt or tampered with. Reject it.
                return new ResponseEntity<>(new ApiResponse("Integrity check failed. File is compromised."), HttpStatus.BAD_REQUEST);
            }

            // Step 4: If all checks pass, save the decrypted file.
            // Note: We need to modify FileStorageService to accept byte[] and a filename.
            fileStorageService.saveFile(decryptedFileBytes, encryptedFile.getOriginalFilename());

            // Step 5: Return a success response.
            return new ResponseEntity<>(new ApiResponse("File uploaded, decrypted, and verified successfully!"), HttpStatus.OK);

        } catch (Exception e) {
            // If any part of the crypto process fails, log the error and return an error message.
            e.printStackTrace();
            return new ResponseEntity<>(new ApiResponse("An error occurred during the cryptographic process: " + e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}