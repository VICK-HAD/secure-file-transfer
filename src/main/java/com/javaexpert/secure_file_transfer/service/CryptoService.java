
package com.javaexpert.secure_file_transfer.service;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;

@Service
public class CryptoService {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("src/main/resources/keystore.p12"), "password".toCharArray());

            String alias = "springboot";

            privateKey = (PrivateKey) keyStore.getKey(alias, "password".toCharArray());

            Certificate certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();

            System.out.println("RSA Key Pair loaded successfully.");

        } catch (Exception e) {
            throw new RuntimeException("Failed to load keystore and keys", e);
        }
    }

    public String getPublicKeyAsBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public SecretKey decryptAesKey(byte[] encryptedAesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
        );

        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);

        byte[] decryptedKeyBytes = cipher.doFinal(encryptedAesKey);

        return new SecretKeySpec(decryptedKeyBytes, "AES");
    }

    public byte[] decryptFile(byte[] encryptedFile, SecretKey aesKey) throws Exception {
        byte[] iv = new byte[12];
        System.arraycopy(encryptedFile, 0, iv, 0, 12);

        byte[] encryptedContent = new byte[encryptedFile.length - 12];
        System.arraycopy(encryptedFile, 12, encryptedContent, 0, encryptedContent.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);
        return cipher.doFinal(encryptedContent);
    }

    public boolean verifyHash(byte[] decryptedFile, String originalHashHex) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] calculatedHashBytes = digest.digest(decryptedFile);

        StringBuilder hexString = new StringBuilder();
        for (byte b : calculatedHashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        String calculatedHashHex = hexString.toString();

        return calculatedHashHex.equalsIgnoreCase(originalHashHex);
    }
}