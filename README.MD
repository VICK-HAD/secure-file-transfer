# Secure File Transfer System

This project is a secure file transfer system built with Java and Spring Boot. It allows a client to upload a file to a web server over a secure connection, ensuring the file's confidentiality, integrity, and authenticity through a multi-layered cryptographic approach.

## Key Features

* **Transport Layer Security (TLS):** All communication between the client and server is encrypted using a TLS/HTTPS connection to prevent eavesdropping.
* **File Encryption (AES-256):** Files are encrypted on the client side using the AES-256 algorithm before being sent to the server, ensuring they are unreadable even if the server is compromised.
* **Secure Key Exchange (RSA):** The symmetric AES key used for file encryption is securely exchanged using the asymmetric RSA algorithm.
* **Data Integrity (SHA-256):** A SHA-256 hash of the file is generated on the client side and verified by the server to ensure the file was not tampered with or corrupted during transit.

## Tech Stack

* **Backend:** Java 17+, Spring Boot
* **Frontend:** HTML, CSS, JavaScript
* **Build Tool:** Maven

## Getting Started

### Prerequisites

* Java Development Kit (JDK) 17 or newer
* Apache Maven
* An IDE like IntelliJ IDEA or VS Code

### Running the Application

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/secure-file-transfer.git](https://github.com/your-username/secure-file-transfer.git)
    cd secure-file-transfer
    ```

2.  **Run the Spring Boot application:**
    You can run the application directly from your IDE by opening the `SecureFileTransferApplication.java` file and running the `main` method.

3.  **Access the application:**
    Once the server is running, you can access the frontend by navigating to `http://localhost:8080` in your web browser.

## API Usage

### File Upload

* **Endpoint:** `POST /api/files/upload`
* **Request Type:** `multipart/form-data`
* **Parts:**
    * `file`: The encrypted file to be uploaded.
    * `hash`: The SHA-256 hash of the original, unencrypted file.
    * `key`: The AES session key, encrypted with the server's public RSA key.