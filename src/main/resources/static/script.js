document.addEventListener('DOMContentLoaded', () => {
    // Page Sections
    const heroSection = document.getElementById('hero-section');
    const authSection = document.getElementById('auth-section');
    const appSection = document.getElementById('app-section');

    // UI Elements
    const tryNowBtn = document.getElementById('try-now-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const showRegisterLink = document.getElementById('show-register');
    const showLoginLink = document.getElementById('show-login');
    const loginFormContainer = document.getElementById('login-form-container');
    const registerFormContainer = document.getElementById('register-form-container');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    // App Elements
    const dropArea = document.getElementById('drop-area');
    const fileInput = document.getElementById('fileInput');
    const fileInfo = document.getElementById('file-info');
    const fileNameSpan = document.getElementById('file-name');
    const uploadBtn = document.getElementById('upload-btn');
    const statusMessage = document.getElementById('statusMessage');

    let selectedFile = null;

    // --- UI Navigation ---
    const showSection = (section) => {
        heroSection.classList.remove('active');
        authSection.classList.remove('active');
        appSection.classList.remove('active');
        section.classList.add('active');
    };

    tryNowBtn.addEventListener('click', () => showSection(authSection));
    logoutBtn.addEventListener('click', () => {
        // Here you would also call a /logout endpoint if using session invalidation
        showSection(heroSection);
    });

    showRegisterLink.addEventListener('click', (e) => {
        e.preventDefault();
        loginFormContainer.classList.add('hidden');
        registerFormContainer.classList.remove('hidden');
    });

    showLoginLink.addEventListener('click', (e) => {
        e.preventDefault();
        registerFormContainer.classList.add('hidden');
        loginFormContainer.classList.remove('hidden');
    });

    // --- Authentication ---
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        // Spring Security's formLogin expects a POST to /login
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        try {
            const response = await fetch('/login', {
                method: 'POST',
                body: new URLSearchParams(formData)
            });

            if (response.ok && response.redirected) {
                // A successful login via formLogin usually results in a redirect
                statusMessage.textContent = 'Login successful!';
                showSection(appSection);
            } else {
                statusMessage.textContent = 'Invalid username or password.';
            }
        } catch (error) {
            statusMessage.textContent = 'Login failed. Server may be down.';
        }
    });

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;

        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                body: new URLSearchParams(formData)
            });

            const result = await response.text();
            alert(result); // Show success/failure message
            if (response.ok) {
                showLoginLink.click();
            }
        } catch (error) {
            alert('Registration failed.');
        }
    });

    // --- Drag and Drop ---
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, () => dropArea.classList.add('highlight'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, () => dropArea.classList.remove('highlight'), false);
    });

    dropArea.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFile(files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        handleFile(e.target.files[0]);
    });

    function handleFile(file) {
        if (file) {
            selectedFile = file;
            fileInfo.classList.remove('hidden');
            fileNameSpan.textContent = file.name;
        }
    }

    // --- Upload and Crypto ---
    uploadBtn.addEventListener('click', async () => {
        if (!selectedFile) return;

        statusMessage.textContent = 'Checking server storage...';

        // **NEW: STORAGE CHECK**
        try {
            const checkResponse = await fetch(`/api/storage/check?fileSize=${selectedFile.size}`);
            const checkData = await checkResponse.json();

            if (!checkData.hasEnoughSpace) {
                statusMessage.textContent = 'Error: Not enough storage space on the server.';
                return;
            }
        } catch (error) {
            statusMessage.textContent = 'Error: Could not check server storage.';
            return;
        }

        // If storage check passes, proceed with crypto workflow.
        await performSecureUpload(selectedFile);
    });

    async function performSecureUpload(file) {
        // This is the full crypto workflow from the previous step.
        statusMessage.textContent = 'Starting secure upload...';

        try {
            // Step 1: Read file content.
            statusMessage.textContent = 'Reading file...';
            const fileBuffer = await file.arrayBuffer();

            // Step 2: Calculate SHA-256 hash of the original file.
            statusMessage.textContent = 'Generating file hash...';
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', fileBuffer);
            const hashHex = bufferToHex(hashBuffer);

            // Step 3: Generate a random AES-GCM key.
            statusMessage.textContent = 'Generating encryption key...';
            const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

            // Step 4: Encrypt the file using the AES key.
            statusMessage.textContent = 'Encrypting file...';
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedFileBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, fileBuffer);

            // Step 5: Fetch the server's public RSA key.
            statusMessage.textContent = 'Fetching server public key...';
            const response = await fetch('/api/security/public-key');
            const keyData = await response.json();
            const rsaPublicKey = await importRsaPublicKey(keyData.publicKey);

            // Step 6: Encrypt the AES key with the server's public RSA key.
            statusMessage.textContent = 'Encrypting session key...';
            const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
            const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPublicKey, exportedAesKey);

            // Step 7: Prepare and send all parts to the server.
            statusMessage.textContent = 'Uploading encrypted data...';
            const formData = new FormData();
            formData.append('file', new Blob([iv, new Uint8Array(encryptedFileBuffer)]), file.name);
            formData.append('key', new Blob([encryptedAesKeyBuffer]), 'aes.key');
            formData.append('hash', hashHex);

            const uploadResponse = await fetch('/api/files/upload', {
                method: 'POST',
                body: formData
            });

            const result = await uploadResponse.json();
            if (uploadResponse.ok) {
                statusMessage.textContent = `Success: ${result.message}`;
            } else {
                statusMessage.textContent = `Error: ${result.message}`;
            }

        } catch (error) {
            console.error('An error occurred:', error);
            statusMessage.textContent = 'A critical error occurred. Check console.';
        }
    }

    // --- Helper Functions ---
    function bufferToHex(buffer) {
        return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    function base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    async function importRsaPublicKey(base64Key) {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        return await window.crypto.subtle.importKey('spki', keyBuffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    }
});