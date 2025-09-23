// All crypto logic (AES, RSA, SHA-256).

package com.javaexpert.secure_file_transfer.service;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;

@Service
public class CryptoService {

    // These will hold the server's RSA public and private keys.
    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * This method runs automatically once when the service is created.
     * Its job is to load the RSA key pair from the keystore file you created.
     */
    @PostConstruct
    public void init() {
        try {
            // The keystore file is located in the `src/main/resources` directory.
            // We need to load it to get our keys.
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            // NOTE: Replace "password" with the actual password you used for your keystore.
            keyStore.load(new FileInputStream("src/main/resources/keystore.p12"), "password".toCharArray());

            // The alias is the name we gave to our key pair when we created it.
            String alias = "springboot";

            // Load the private key from the keystore.
            // We need the private key to decrypt the AES key sent by the client.
            // Note: The password here is the same as the keystore password.
            privateKey = (PrivateKey) keyStore.getKey(alias, "password".toCharArray());

            // Load the public key from the certificate in the keystore.
            // We will send this public key to the client so it can encrypt the AES key.
            Certificate certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();

            System.out.println("RSA Key Pair loaded successfully.");

        } catch (Exception e) {
            // If the keys can't be loaded, the application can't function securely.
            // Throw a runtime exception to stop the application from starting.
            throw new RuntimeException("Failed to load keystore and keys", e);
        }
    }

    /**
     * Returns the server's public key, encoded as a Base64 string.
     * The client will fetch this key to encrypt the AES session key.
     * @return Base64 encoded public key string.
     */
    public String getPublicKeyAsBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Decrypts an AES session key that was encrypted with our public RSA key.
     * @param encryptedAesKey The encrypted AES key (as a byte array).
     * @return The decrypted AES key as a SecretKey object.
     */
    public SecretKey decryptAesKey(byte[] encryptedAesKey) throws Exception {
        // Get an instance of the RSA cipher.
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // Initialize the cipher for decryption mode with our private key.
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // Decrypt the data.
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedAesKey);
        // The decrypted bytes represent the AES key. We wrap them in a SecretKeySpec.
        return new SecretKeySpec(decryptedKeyBytes, "AES");
    }

    /**
     * Decrypts the file content using the provided AES key.
     * @param encryptedFile The encrypted file data, including the IV.
     * @param aesKey The decrypted AES session key.
     * @return The original, decrypted file data as a byte array.
     */
    public byte[] decryptFile(byte[] encryptedFile, SecretKey aesKey) throws Exception {
        // The first 12 bytes of the encrypted data are the Initialization Vector (IV).
        byte[] iv = new byte[12];
        System.arraycopy(encryptedFile, 0, iv, 0, 12);

        // The rest of the data is the actual encrypted file content.
        byte[] encryptedContent = new byte[encryptedFile.length - 12];
        System.arraycopy(encryptedFile, 12, encryptedContent, 0, encryptedContent.length);

        // Get an instance of the AES/GCM cipher. GCM is a modern, secure mode.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Create the GCM parameter spec with the IV. The 128 is the tag length.
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        // Initialize the cipher for decryption mode with the AES key and IV.
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);
        // Decrypt the file content.
        return cipher.doFinal(encryptedContent);
    }

    /**
     * Verifies the integrity of the decrypted file by comparing its hash
     * with the original hash sent by the client.
     * @param decryptedFile The decrypted file data.
     * @param originalHashHex The SHA-256 hash sent by the client (in hex format).
     * @return true if the hashes match, false otherwise.
     */
    public boolean verifyHash(byte[] decryptedFile, String originalHashHex) throws Exception {
        // Calculate the SHA-256 hash of the decrypted file.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] calculatedHashBytes = digest.digest(decryptedFile);

        // Convert the calculated hash byte array to a hexadecimal string.
        StringBuilder hexString = new StringBuilder();
        for (byte b : calculatedHashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        String calculatedHashHex = hexString.toString();

        // Compare the calculated hash with the original hash from the client.
        // This comparison is case-insensitive to be safe.
        return calculatedHashHex.equalsIgnoreCase(originalHashHex);
    }
}