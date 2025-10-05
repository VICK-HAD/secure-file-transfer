document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('fileInput');
    const statusMessage = document.getElementById('statusMessage');

    uploadForm.addEventListener('submit', async (event) => {
        // Prevent the default form submission which reloads the page.
        event.preventDefault();

        const file = fileInput.files[0];
        if (!file) {
            statusMessage.textContent = 'Please select a file to upload.';
            return;
        }

        // Create a FormData object to hold the file data.
        const formData = new FormData();
        formData.append('file', file);

        statusMessage.textContent = 'Uploading...';

        try {
            // Use fetch to send the file to your Spring Boot backend.
            // Replace the URL if your server is running on a different port or address.
            const response = await fetch('/api/files/upload', {
                method: 'POST',
                body: formData,
            });

            // Get the plain text response from the server.
            const result = await response.text();

            if (response.ok) {
                statusMessage.textContent = `Success: ${result}`;
            } else {
                statusMessage.textContent = `Error: ${result}`;
            }
        } catch (error) {
            console.error('Error during upload:', error);
            statusMessage.textContent = 'Upload failed. Check the console for details.';
        }
    });
});