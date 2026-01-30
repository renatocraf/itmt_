// Custom JavaScript for Threat Modeling Tool

document.addEventListener('DOMContentLoaded', function() {
    // File upload drag and drop
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.querySelector('#tm7_file');
    
    if (uploadArea && fileInput) {
        uploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileInfo(files[0]);
            }
        });
        
        fileInput.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                updateFileInfo(e.target.files[0]);
            }
        });
        
        uploadArea.addEventListener('click', function() {
            fileInput.click();
        });
    }
    
    // Update file info display
    function updateFileInfo(file) {
        const fileInfo = document.querySelector('.file-info');
        if (fileInfo) {
            fileInfo.innerHTML = `
                <strong>Selected file:</strong> ${file.name}<br>
                <small>Size: ${(file.size / 1024).toFixed(2)} KB</small>
            `;
            fileInfo.style.display = 'block';
        }
    }
    
    // Show spinner on form submission
    document.addEventListener('submit', function(e) {
        const form = e.target;
        if (form.tagName !== 'FORM') return;

        let loadingText = "Loading...";
        if (form.id === 'analysisForm') {
            loadingText = "Performing Analysis. This may take a few minutes.";
        } else if (form.action && form.action.includes('rag-enhance')) {
            loadingText = "Enhancing with RAG. Please wait...";
        }

        const spinner = document.createElement('div');
        spinner.className = 'spinner-overlay';
        spinner.innerHTML = `
            <div class="text-center">
                <div class="spinner-border spinner-border-lg text-light mb-3" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <div class="text-light fw-bold">${loadingText}</div>
            </div>
        `;
        document.body.appendChild(spinner);
    });

    // Auto-dismiss flash messages after configured time (default 5s)
    document.querySelectorAll('[data-auto-dismiss]').forEach(function(el) {
        var ms = parseInt(el.getAttribute('data-auto-dismiss'), 10) || 10000;
        setTimeout(function() {
            var bsAlert = bootstrap.Alert.getOrCreateInstance(el);
            bsAlert.close();
        }, ms);
    });
    
    // Toggle API key field based on model selection
    const modelSelect = document.querySelector('#model');
    const apiKeyField = document.querySelector('#api_key');
    const serverIpField = document.querySelector('#server_ip');
    
    if (modelSelect && apiKeyField && serverIpField) {
        function toggleFields() {
            const selectedModel = modelSelect.value;
            const apiKeyGroup = apiKeyField.closest('.mb-3');
            const serverIpGroup = serverIpField.closest('.mb-3');
            
            if (selectedModel === 'qwen3:8b') {
                apiKeyGroup.style.display = 'none';
                serverIpGroup.style.display = 'block';
            } else {
                apiKeyGroup.style.display = 'block';
                serverIpGroup.style.display = 'none';
            }
        }
        
        modelSelect.addEventListener('change', toggleFields);
        toggleFields(); // Initial call
    }
});

