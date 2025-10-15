document.addEventListener('DOMContentLoaded', () => {
    const heroSection = document.getElementById('hero');
    const authSection = document.getElementById('auth');
    const appSection = document.getElementById('app');
    const tryNowBtn = document.getElementById('tryNowBtn');
    const toggleAuth = document.getElementById('toggleAuth');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const authTitle = document.getElementById('authTitle');
    const uploadBtn = document.getElementById('uploadBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const dropArea = document.getElementById('dropArea');
    const fileInput = document.getElementById('fileInput');
    const fileNameSpan = document.getElementById('fileName');
    const statusMsg = document.getElementById('statusMsg');
    let selectedFile = null;

    const showSection = (section) => {
        heroSection.classList.add('hidden');
        authSection.classList.add('hidden');
        appSection.classList.add('hidden');
        section.classList.remove('hidden');
    };

    tryNowBtn.addEventListener('click', () => showSection(authSection));

    toggleAuth.addEventListener('click', (e) => {
        e.preventDefault();
        if (loginForm.classList.contains('hidden')) {
            loginForm.classList.remove('hidden');
            registerForm.classList.add('hidden');
            authTitle.textContent = 'Login';
            toggleAuth.textContent = "Don’t have an account? Register";
        } else {
            loginForm.classList.add('hidden');
            registerForm.classList.remove('hidden');
            authTitle.textContent = 'Register';
            toggleAuth.textContent = "Already have an account? Login";
        }
    });

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);
        try {
            const response = await fetch('/login', { method: 'POST', body: new URLSearchParams(formData) });
            if (response.ok) {
                statusMsg.textContent = '';
                showSection(appSection);
            } else {
                alert('Invalid username or password.');
            }
        } catch (error) {
            alert('Login failed. Server may be down.');
        }
    });

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('regUsername').value;
        const password = document.getElementById('regPassword').value;
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);
        try {
            const response = await fetch('/api/auth/register', { method: 'POST', body: new URLSearchParams(formData), credentials: 'include' });
            const result = await response.text();
            alert(result);
            if (response.ok) { toggleAuth.click(); }
        } catch (error) {
            alert('Registration failed.');
        }
    });

    logoutBtn.addEventListener('click', async () => {
        await fetch('/logout', { method: 'POST', credentials: 'include' });
        showSection(heroSection);
    });

    dropArea.addEventListener('click', () => fileInput.click());
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => dropArea.addEventListener(eventName, preventDefaults, false));
    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
    ['dragenter', 'dragover'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.add('dragover'), false));
    ['dragleave', 'drop'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.remove('dragover'), false));

    dropArea.addEventListener('drop', (e) => {
        handleFileSelect(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', (e) => {
        handleFileSelect(e.target.files[0]);
    });

    async function handleFileSelect(file) {
        if (!file) return;
        selectedFile = file;
        fileNameSpan.textContent = `Selected: ${file.name}`;
        statusMsg.textContent = 'Checking server prerequisites...';
        uploadBtn.classList.add('hidden');
        try {
            const checkResponse = await fetch(`/api/storage/check?fileSize=${selectedFile.size}`, { credentials: 'include' });
            if (!checkResponse.ok) throw new Error('Storage check request failed.');
            const checkData = await checkResponse.json();
            if (!checkData.hasEnoughSpace) {
                statusMsg.textContent = 'Error: Not enough storage space on the server.';
                return;
            }
            const keyResponse = await fetch('/api/security/public-key', { credentials: 'include' });
            if (!keyResponse.ok) throw new Error('Could not fetch security key.');
            statusMsg.textContent = 'Ready to encrypt and upload.';
            uploadBtn.classList.remove('hidden');
        } catch (error) {
            console.error('Prerequisite check failed:', error);
            statusMsg.textContent = `Error: ${error.message}`;
            fileNameSpan.textContent = '';
        }
    }

    uploadBtn.addEventListener('click', async () => {
        if (!selectedFile) return;
        await performSecureUpload(selectedFile);
    });

    async function performSecureUpload(file) {
        statusMsg.textContent = 'Starting secure upload...';
        try {
            statusMsg.textContent = 'Encrypting file...';
            const fileBuffer = await file.arrayBuffer();
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', fileBuffer);
            const hashHex = bufferToHex(hashBuffer);
            const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encryptedFileBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, fileBuffer);
            statusMsg.textContent = 'Fetching server public key for encryption...';
            const response = await fetch('/api/security/public-key', { credentials: 'include' });
            const keyData = await response.json();
            const rsaPublicKey = await importRsaPublicKey(keyData.publicKey);
            const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
            const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPublicKey, exportedAesKey);
            statusMsg.textContent = 'Uploading encrypted data...';
            const formData = new FormData();
            formData.append('file', new Blob([iv, new Uint8Array(encryptedFileBuffer)]), file.name);
            formData.append('key', new Blob([encryptedAesKeyBuffer]), 'aes.key');
            formData.append('hash', hashHex);
            const uploadResponse = await fetch('/api/files/upload', { method: 'POST', body: formData, credentials: 'include' });
            if (uploadResponse.redirected && uploadResponse.url.includes('/login')) {
                statusMsg.textContent = 'Error: Your session has expired. Please log out and log back in.';
                return;
            }
            const result = await uploadResponse.json();
            if (uploadResponse.ok) {
                statusMsg.textContent = `Success: ${result.message}`;
            } else {
                statusMsg.textContent = `Error: ${result.message}`;
            }
        } catch (error) {
            console.error('An error occurred:', error);
            statusMsg.textContent = 'A critical error occurred. Check console.';
        }
    }

    function bufferToHex(buffer) { return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join(''); }
    function base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) { bytes[i] = binaryString.charCodeAt(i); }
        return bytes.buffer;
    }
    async function importRsaPublicKey(base64Key) {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        return await window.crypto.subtle.importKey('spki', keyBuffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    }

    showSection(heroSection);
});

//document.addEventListener('DOMContentLoaded', () => {
//    const heroSection = document.getElementById('hero-section');
//    const authSection = document.getElementById('auth-section');
//    const appSection = document.getElementById('app-section');
//
//    const tryNowBtn = document.getElementById('try-now-btn');
//    const logoutBtn = document.getElementById('logout-btn');
//    const showRegisterLink = document.getElementById('show-register');
//    const showLoginLink = document.getElementById('show-login');
//    const loginFormContainer = document.getElementById('login-form-container');
//    const registerFormContainer = document.getElementById('register-form-container');
//    const loginForm = document.getElementById('login-form');
//    const registerForm = document.getElementById('register-form');
//
//    const dropArea = document.getElementById('drop-area');
//    const fileInput = document.getElementById('fileInput');
//    const fileInfo = document.getElementById('file-info');
//    const fileNameSpan = document.getElementById('file-name');
//    const uploadBtn = document.getElementById('upload-btn');
//    const statusMessage = document.getElementById('statusMessage');
//
//    let selectedFile = null;
//
//    // --- UI Navigation (No changes needed) ---
//    const showSection = (section) => {
//        heroSection.classList.remove('active');
//        authSection.classList.remove('active');
//        appSection.classList.remove('active');
//        section.classList.add('active');
//    };
//    tryNowBtn.addEventListener('click', () => showSection(authSection));
//    logoutBtn.addEventListener('click', async () => {
//        await fetch('/logout', { method: 'POST', credentials: 'include' });
//        showSection(heroSection);
//    });
//    showRegisterLink.addEventListener('click', (e) => {
//        e.preventDefault();
//        loginFormContainer.classList.add('hidden');
//        registerFormContainer.classList.remove('hidden');
//    });
//    showLoginLink.addEventListener('click', (e) => {
//        e.preventDefault();
//        registerFormContainer.classList.add('hidden');
//        loginFormContainer.classList.remove('hidden');
//    });
//
//    // --- Authentication (No changes needed) ---
//    loginForm.addEventListener('submit', async (e) => {
//        e.preventDefault();
//        const username = document.getElementById('login-username').value;
//        const password = document.getElementById('login-password').value;
//        const formData = new FormData();
//        formData.append('username', username);
//        formData.append('password', password);
//        try {
//            const response = await fetch('/login', { method: 'POST', body: new URLSearchParams(formData) });
//            if (response.ok) {
//                statusMessage.textContent = '';
//                showSection(appSection);
//            } else {
//                alert('Invalid username or password.');
//            }
//        } catch (error) {
//            alert('Login failed. Server may be down.');
//        }
//    });
//    registerForm.addEventListener('submit', async (e) => {
//        e.preventDefault();
//        const username = document.getElementById('register-username').value;
//        const password = document.getElementById('register-password').value;
//        const formData = new FormData();
//        formData.append('username', username);
//        formData.append('password', password);
//        try {
//            const response = await fetch('/api/auth/register', { method: 'POST', body: new URLSearchParams(formData), credentials: 'include' });
//            const result = await response.text();
//            alert(result);
//            if (response.ok) { showLoginLink.click(); }
//        } catch (error) {
//            alert('Registration failed.');
//        }
//    });
//
//    // --- File Selection Logic (UPDATED) ---
//    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => dropArea.addEventListener(eventName, preventDefaults, false));
//    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
//    ['dragenter', 'dragover'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.add('highlight'), false));
//    ['dragleave', 'drop'].forEach(eventName => dropArea.addEventListener(eventName, () => dropArea.classList.remove('highlight'), false));
//
//    dropArea.addEventListener('drop', (e) => {
//        const dt = e.dataTransfer;
//        const files = dt.files;
//        handleFileSelect(files[0]);
//    });
//    fileInput.addEventListener('change', (e) => {
//        handleFileSelect(e.target.files[0]);
//    });
//
//    async function handleFileSelect(file) {
//        if (!file) return;
//
//        selectedFile = file;
//        fileNameSpan.textContent = file.name;
//        statusMessage.textContent = 'Checking server prerequisites...';
//
//        // Show the file info, but hide the upload button until checks are done.
//        fileInfo.classList.remove('hidden');
//        uploadBtn.style.display = 'none';
//
//        try {
//            // Step 1: Immediately perform storage check
//            const checkResponse = await fetch(`/api/storage/check?fileSize=${selectedFile.size}`, { credentials: 'include' });
//            if (!checkResponse.ok) throw new Error('Storage check request failed.');
//            const checkData = await checkResponse.json();
//            if (!checkData.hasEnoughSpace) {
//                statusMessage.textContent = 'Error: Not enough storage space on the server.';
//                return;
//_            }
//
//            // Step 2: Immediately fetch the public key
//            const keyResponse = await fetch('/api/security/public-key', { credentials: 'include' });
//            if (!keyResponse.ok) throw new Error('Could not fetch security key.');
//
//            // If both checks pass, show the upload button and a ready message.
//            statusMessage.textContent = 'Ready to encrypt and upload.';
//            uploadBtn.style.display = 'inline-block';
//
//        } catch (error) {
//            console.error('Prerequisite check failed:', error);
//            statusMessage.textContent = `Error: ${error.message}`;
//            fileInfo.classList.add('hidden');
//        }
//    }
//
//    // --- Upload Button Logic (UPDATED) ---
//    uploadBtn.addEventListener('click', async () => {
//        if (!selectedFile) return;
//        // The button's only job now is to call the final upload function.
//        await performSecureUpload(selectedFile);
//    });
//
//    // This function remains mostly the same, but no longer needs to do the pre-checks.
//    async function performSecureUpload(file) {
//        statusMessage.textContent = 'Starting secure upload...';
//
//        try {
//            statusMessage.textContent = 'Encrypting file...';
//            const fileBuffer = await file.arrayBuffer();
//            const hashBuffer = await window.crypto.subtle.digest('SHA-256', fileBuffer);
//            const hashHex = bufferToHex(hashBuffer);
//            const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
//            const iv = window.crypto.getRandomValues(new Uint8Array(12));
//            const encryptedFileBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, fileBuffer);
//
//            statusMessage.textContent = 'Fetching server public key again for encryption...';
//            const response = await fetch('/api/security/public-key', { credentials: 'include' });
//            const keyData = await response.json();
//            const rsaPublicKey = await importRsaPublicKey(keyData.publicKey);
//
//            const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
//            const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPublicKey, exportedAesKey);
//
//            statusMessage.textContent = 'Uploading encrypted data...';
//            const formData = new FormData();
//            formData.append('file', new Blob([iv, new Uint8Array(encryptedFileBuffer)]), file.name);
//            formData.append('key', new Blob([encryptedAesKeyBuffer]), 'aes.key');
//            formData.append('hash', hashHex);
//
//            const uploadResponse = await fetch('/api/files/upload', { method: 'POST', body: formData, credentials: 'include' });
//
//            if (uploadResponse.redirected && uploadResponse.url.includes('/login')) {
//                statusMessage.textContent = 'Error: Your session has expired. Please log out and log back in.';
//                return;
//            }
//
//            const result = await uploadResponse.json();
//            if (uploadResponse.ok) {
//                statusMessage.textContent = `Success: ${result.message}`;
//            } else {
//                statusMessage.textContent = `Error: ${result.message}`;
//            }
//
//        } catch (error) {
//            console.error('An error occurred:', error);
//            statusMessage.textContent = 'A critical error occurred. Check console.';
//        }
//    }
//
//    // --- Helper Functions (No changes needed) ---
//    function bufferToHex(buffer) { return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join(''); }
//    function base64ToArrayBuffer(base64) {
//        const binaryString = window.atob(base64);
//        const len = binaryString.length;
//        const bytes = new Uint8Array(len);
//        for (let i = 0; i < len; i++) { bytes[i] = binaryString.charCodeAt(i); }
//        return bytes.buffer;
//    }
//    async function importRsaPublicKey(base64Key) {
//        const keyBuffer = base64ToArrayBuffer(base64Key);
//        return await window.crypto.subtle.importKey('spki', keyBuffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
//    }
//});
//
////document.addEventListener('DOMContentLoaded', () => {
////    const heroSection = document.getElementById('hero-section');
////    const authSection = document.getElementById('auth-section');
////    const appSection = document.getElementById('app-section');
////
////    const tryNowBtn = document.getElementById('try-now-btn');
////    const logoutBtn = document.getElementById('logout-btn');
////    const showRegisterLink = document.getElementById('show-register');
////    const showLoginLink = document.getElementById('show-login');
////    const loginFormContainer = document.getElementById('login-form-container');
////    const registerFormContainer = document.getElementById('register-form-container');
////    const loginForm = document.getElementById('login-form');
////    const registerForm = document.getElementById('register-form');
////
////    const dropArea = document.getElementById('drop-area');
////    const fileInput = document.getElementById('fileInput');
////    const fileInfo = document.getElementById('file-info');
////    const fileNameSpan = document.getElementById('file-name');
////    const uploadBtn = document.getElementById('upload-btn');
////    const statusMessage = document.getElementById('statusMessage');
////
////    let selectedFile = null;
////
////    const showSection = (section) => {
////        heroSection.classList.remove('active');
////        authSection.classList.remove('active');
////        appSection.classList.remove('active');
////        section.classList.add('active');
////    };
////
////    tryNowBtn.addEventListener('click', () => showSection(authSection));
////
////    logoutBtn.addEventListener('click', async () => {
////        await fetch('/logout', { method: 'POST', credentials: 'include' }); // <-- CHANGE ADDED
////        showSection(heroSection);
////    });
////
////    showRegisterLink.addEventListener('click', (e) => {
////        e.preventDefault();
////        loginFormContainer.classList.add('hidden');
////        registerFormContainer.classList.remove('hidden');
////    });
////
////    showLoginLink.addEventListener('click', (e) => {
////        e.preventDefault();
////        registerFormContainer.classList.add('hidden');
////        loginFormContainer.classList.remove('hidden');
////    });
////
////    loginForm.addEventListener('submit', async (e) => {
////        e.preventDefault();
////        const username = document.getElementById('login-username').value;
////        const password = document.getElementById('login-password').value;
////        const formData = new FormData();
////        formData.append('username', username);
////        formData.append('password', password);
////
////        try {
////            const response = await fetch('/login', {
////                method: 'POST',
////                body: new URLSearchParams(formData)
////            });
////
////            if (response.ok) {
////                statusMessage.textContent = 'Login successful!';
////                showSection(appSection);
////            } else {
////                statusMessage.textContent = 'Invalid username or password.';
////            }
////        } catch (error) {
////            statusMessage.textContent = 'Login failed. Server may be down.';
////        }
////    });
////
////    registerForm.addEventListener('submit', async (e) => {
////        e.preventDefault();
////        const username = document.getElementById('register-username').value;
////        const password = document.getElementById('register-password').value;
////        const formData = new FormData();
////        formData.append('username', username);
////        formData.append('password', password);
////
////        try {
////            const response = await fetch('/api/auth/register', {
////                method: 'POST',
////                body: new URLSearchParams(formData),
////                credentials: 'include'
////            });
////
////            const result = await response.text();
////            alert(result);
////            if (response.ok) {
////                showLoginLink.click();
////            }
////        } catch (error) {
////            alert('Registration failed.');
////        }
////    });
////
////    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
////        dropArea.addEventListener(eventName, preventDefaults, false);
////    });
////    function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
////    ['dragenter', 'dragover'].forEach(eventName => {
////        dropArea.addEventListener(eventName, () => dropArea.classList.add('highlight'), false);
////    });
////    ['dragleave', 'drop'].forEach(eventName => {
////        dropArea.addEventListener(eventName, () => dropArea.classList.remove('highlight'), false);
////    });
////    dropArea.addEventListener('drop', (e) => {
////        const dt = e.dataTransfer;
////        const files = dt.files;
////        handleFile(files[0]);
////    });
////    fileInput.addEventListener('change', (e) => {
////        handleFile(e.target.files[0]);
////    });
////    function handleFile(file) {
////        if (file) {
////            selectedFile = file;
////            fileInfo.classList.remove('hidden');
////            fileNameSpan.textContent = file.name;
////        }
////    }
////
////    uploadBtn.addEventListener('click', async () => {
////        if (!selectedFile) return;
////
////        statusMessage.textContent = 'Checking server storage...';
////
////        try {
////            const checkResponse = await fetch(`/api/storage/check?fileSize=${selectedFile.size}`, { credentials: 'include' });
////            const checkData = await checkResponse.json();
////
////            if (!checkData.hasEnoughSpace) {
////                statusMessage.textContent = 'Error: Not enough storage space on the server.';
////                return;
////            }
////        } catch (error) {
////            statusMessage.textContent = 'Error: Could not check server storage.';
////            return;
////        }
////
////        await performSecureUpload(selectedFile);
////    });
////
////    async function performSecureUpload(file) {
////        statusMessage.textContent = 'Starting secure upload...';
////
////        try {
////            statusMessage.textContent = 'Fetching server public key...';
////            const response = await fetch('/api/security/public-key', { credentials: 'include' });
////
////            const keyData = await response.json();
////            const fileBuffer = await file.arrayBuffer();
////            const hashBuffer = await window.crypto.subtle.digest('SHA-256', fileBuffer);
////            const hashHex = bufferToHex(hashBuffer);
////            const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
////            const iv = window.crypto.getRandomValues(new Uint8Array(12));
////            const encryptedFileBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, fileBuffer);
////            const rsaPublicKey = await importRsaPublicKey(keyData.publicKey);
////            const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
////            const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPublicKey, exportedAesKey);
////
////            statusMessage.textContent = 'Uploading encrypted data...';
////            const formData = new FormData();
////            formData.append('file', new Blob([iv, new Uint8Array(encryptedFileBuffer)]), file.name);
////            formData.append('key', new Blob([encryptedAesKeyBuffer]), 'aes.key');
////            formData.append('hash', hashHex);
////
////            const uploadResponse = await fetch('/api/files/upload', {
////                method: 'POST',
////                body: formData,
////                credentials: 'include'
////            });
////
////            if (uploadResponse.redirected && uploadResponse.url.includes('/login')) {
////                statusMessage.textContent = 'Error: Your session has expired. Please log out and log back in.';
////                return;
////            }
////
////            const result = await uploadResponse.json();
////            if (uploadResponse.ok) {
////                statusMessage.textContent = `Success: ${result.message}`;
////            } else {
////                statusMessage.textContent = `Error: ${result.message}`;
////            }
////
////        } catch (error) {
////            console.error('An error occurred:', error);
////            statusMessage.textContent = 'A critical error occurred. Check console.';
////        }
////    }
////
////    function bufferToHex(buffer) { return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join(''); }
////    function base64ToArrayBuffer(base64) {
////        const binaryString = window.atob(base64);
////        const len = binaryString.length;
////        const bytes = new Uint8Array(len);
////        for (let i = 0; i < len; i++) { bytes[i] = binaryString.charCodeAt(i); }
////        return bytes.buffer;
////    }
////    async function importRsaPublicKey(base64Key) {
////        const keyBuffer = base64ToArrayBuffer(base64Key);
////        return await window.crypto.subtle.importKey('spki', keyBuffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
////    }
////});