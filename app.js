// Matrix Vault Pro - Secure Password Manager
// Version 2.0.0 - Enhanced Security & Performance

// Constants
const STORAGE_KEY = 'matrix_vault_data';
const VAULT_VERSION = '2.0.0';
const DEFAULT_ITERATION_COUNT = 100000;
const AES_KEY_SIZE = 256; // bits
const ANIMATION_STORAGE_KEY = 'animation_level';
const SECURITY_LEVEL_STORAGE_KEY = 'security_level';

// App state
let vault = {
    passwords: [],
    salt: null,
    iv: null,
    iterationCount: DEFAULT_ITERATION_COUNT,
    version: VAULT_VERSION,
    lastAccess: null
};

let masterKey = null;
let currentActivePasswordId = null;
let animationLevel = localStorage.getItem(ANIMATION_STORAGE_KEY) || 'full';

// DOM Elements
const elements = {
    // Screens
    loginScreen: document.getElementById('login-screen'),
    vaultScreen: document.getElementById('vault-screen'),
    
    // Modals
    addPasswordModal: document.getElementById('add-password-modal'),
    editPasswordModal: document.getElementById('edit-password-modal'),
    exportModal: document.getElementById('export-modal'),
    importModal: document.getElementById('import-modal'),
    passwordDetailModal: document.getElementById('password-detail-modal'),
    settingsModal: document.getElementById('settings-modal'),
    changeMasterModal: document.getElementById('change-master-modal'),
    
    // Login screen elements
    masterPassword: document.getElementById('master-password'),
    loginBtn: document.getElementById('login-btn'),
    createVaultBtn: document.getElementById('create-vault-btn'),
    changeMasterBtn: document.getElementById('change-master-btn'),
    
    // Vault screen elements
    addBtn: document.getElementById('add-btn'),
    exportBtn: document.getElementById('export-btn'),
    importBtn: document.getElementById('import-btn'),
    logoutBtn: document.getElementById('logout-btn'),
    settingsBtn: document.getElementById('settings-btn'),
    searchInput: document.getElementById('search-input'),
    passwordList: document.getElementById('password-list'),
    entryCount: document.getElementById('entry-count'),
    vaultStatus: document.getElementById('vault-status'),
    
    // Add password modal elements
    newTitle: document.getElementById('new-title'),
    newUsername: document.getElementById('new-username'),
    newPassword: document.getElementById('new-password'),
    newTogglePassword: document.getElementById('new-toggle-password'),
    newUrl: document.getElementById('new-url'),
    newNotes: document.getElementById('new-notes'),
    newPasswordStrength: document.getElementById('new-password-strength'),
    passwordMeterBar: document.getElementById('password-meter-bar'),
    generatePasswordBtn: document.getElementById('generate-password-btn'),
    savePasswordBtn: document.getElementById('save-password-btn'),
    cancelAddBtn: document.getElementById('cancel-add-btn'),
    
    // Edit password modal elements
    editId: document.getElementById('edit-id'),
    editTitle: document.getElementById('edit-title'),
    editUsername: document.getElementById('edit-username'),
    editPassword: document.getElementById('edit-password'),
    editTogglePassword: document.getElementById('edit-toggle-password'),
    editUrl: document.getElementById('edit-url'),
    editNotes: document.getElementById('edit-notes'),
    updatePasswordBtn: document.getElementById('update-password-btn'),
    deletePasswordBtn: document.getElementById('delete-password-btn'),
    cancelEditBtn: document.getElementById('cancel-edit-btn'),
    
    // Export modal elements
    exportPassword: document.getElementById('export-password'),
    confirmExportPassword: document.getElementById('confirm-export-password'),
    confirmExportBtn: document.getElementById('confirm-export-btn'),
    cancelExportBtn: document.getElementById('cancel-export-btn'),
    exportText: document.getElementById('export-text'),
    copyExportBtn: document.getElementById('copy-export-btn'),
    
    // Import modal elements
    importText: document.getElementById('import-text'),
    importPassword: document.getElementById('import-password'),
    confirmImportBtn: document.getElementById('confirm-import-btn'),
    cancelImportBtn: document.getElementById('cancel-import-btn'),
    
    // Password detail modal elements
    detailTitle: document.getElementById('detail-title'),
    detailUsername: document.getElementById('detail-username'),
    detailPassword: document.getElementById('detail-password'),
    detailUrl: document.getElementById('detail-url'),
    detailUrlLink: document.getElementById('detail-url-link'),
    detailNotes: document.getElementById('detail-notes'),
    detailCreated: document.getElementById('detail-created'),
    detailUpdated: document.getElementById('detail-updated'),
    urlContainer: document.getElementById('url-container'),
    notesContainer: document.getElementById('notes-container'),
    editEntryBtn: document.getElementById('edit-entry-btn'),
    closeDetailBtn: document.getElementById('close-detail-btn'),
    
    // Settings modal elements
    securityLevel: document.getElementById('security-level'),
    closeSettingsBtn: document.getElementById('close-settings-btn'),
    autoLogout: document.getElementById('auto-logout'),
    clearDataBtn: document.getElementById('clear-data-btn'),
    animationLevel: document.getElementById('animation-level'),
    logoutTimer: document.getElementById('logout-timer'),
    
    // Change master password modal elements
    currentMaster: document.getElementById('current-master'),
    newMaster: document.getElementById('new-master'),
    confirmNewMaster: document.getElementById('confirm-new-master'),
    masterPasswordStrength: document.getElementById('master-password-strength'),
    masterPasswordMeterBar: document.getElementById('master-password-meter-bar'),
    confirmChangeMasterBtn: document.getElementById('confirm-change-master-btn'),
    cancelChangeMasterBtn: document.getElementById('cancel-change-master-btn'),
    
    // Other elements
    notification: document.getElementById('notification'),
    notificationMessage: document.querySelector('.notification-message'),
    matrixBackground: document.getElementById('matrix-background'),
    particlesBackground: document.getElementById('particles-background'),
};

// Utility Functions

// Encrypt and sanitize text to prevent XSS attacks
function sanitizeText(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Format date to readable format
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString();
}

// UI helper functions
function showModal(modalElement) {
    if (!modalElement) return;
    
    // Add accessibility attributes
    modalElement.setAttribute('role', 'dialog');
    modalElement.setAttribute('aria-modal', 'true');
    
    // Reset any validation errors
    modalElement.querySelectorAll('.input-error').forEach(el => el.remove());
    
    // Check for CSRF token
    const csrfToken = generateCSRFToken();
    localStorage.setItem('csrf_token', csrfToken);
    
    // If there's a close button, set focus to it for accessibility
    const closeBtn = modalElement.querySelector('.close-btn');
    if (closeBtn) {
        setTimeout(() => closeBtn.focus(), 100);
    }
    
    modalElement.style.display = 'block';
    
    // Add ESC key listener to close modal
    document.addEventListener('keydown', handleEscKeyForModal);
}

function hideModal(modalElement) {
    if (!modalElement) return;
    modalElement.style.display = 'none';
    
    // Remove ESC key listener
    document.removeEventListener('keydown', handleEscKeyForModal);
}

function handleEscKeyForModal(e) {
    if (e.key === 'Escape') {
        const visibleModal = document.querySelector('.modal[style*="display: block"]');
        if (visibleModal) {
            hideModal(visibleModal);
        }
    }
}

function showNotification(message, type = 'success', duration = 3000) {
    elements.notificationMessage.textContent = message;
    
    // Set icon based on notification type
    const iconElement = elements.notification.querySelector('.notification-icon');
    
    if (type === 'success') {
        iconElement.style.backgroundColor = '#33ff33';
        iconElement.style.mask = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/%3E%3C/svg%3E\") no-repeat 50% 50%";
        iconElement.style.webkitMask = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/%3E%3C/svg%3E\") no-repeat 50% 50%";
    } else if (type === 'error') {
        iconElement.style.backgroundColor = '#ff3333';
        iconElement.style.mask = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z'/%3E%3C/svg%3E\") no-repeat 50% 50%";
        iconElement.style.webkitMask = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z'/%3E%3C/svg%3E\") no-repeat 50% 50%";
    } else if (type === 'warning') {
        iconElement.style.backgroundColor = '#ffcc00';
        iconElement.style.mask = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z'/%3E%3C/svg%3E\") no-repeat 50% 50%";
        iconElement.style.webkitMask = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z'/%3E%3C/svg%3E\") no-repeat 50% 50%";
    }
    
    elements.notification.classList.add('show');
    
    // Clear any existing timeout
    if (window.notificationTimeout) {
        clearTimeout(window.notificationTimeout);
    }
    
    // Set timeout to hide notification
    window.notificationTimeout = setTimeout(() => {
        elements.notification.classList.remove('show');
    }, duration);
}

function clearForm(formModal) {
    const inputs = formModal.querySelectorAll('input, textarea');
    inputs.forEach(input => {
        if (input.type !== 'hidden') {
            input.value = '';
        }
    });
    
    // Reset any password strength indicators
    const strengthIndicators = formModal.querySelectorAll('.password-strength');
    strengthIndicators.forEach(indicator => {
        indicator.textContent = '';
        indicator.className = 'password-strength';
    });
    
    // Reset meter bars
    const meterBars = formModal.querySelectorAll('.password-meter-bar');
    meterBars.forEach(bar => {
        bar.style.width = '0';
        bar.style.backgroundColor = '#333';
    });
}

function showScreen(screenElement) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    screenElement.classList.add('active');
    
    // If showing the vault screen, update the entry count
    if (screenElement === elements.vaultScreen) {
        updateEntryCount();
    }
}

function updateEntryCount() {
    if (elements.entryCount) {
        elements.entryCount.textContent = `${vault.passwords.length} entries`;
    }
}

// Toggle password visibility
function togglePasswordVisibility(inputElement, buttonElement) {
    if (inputElement.type === 'password') {
        inputElement.type = 'text';
        buttonElement.textContent = 'HIDE';
    } else {
        inputElement.type = 'password';
        buttonElement.textContent = 'SHOW';
    }
}

// Show/hide loading indicator with progress feedback
function showLoader(message = 'Processing...', showProgress = false) {
    if (document.getElementById('loader')) {
        document.getElementById('loader').remove();
    }
    
    const loaderElement = document.createElement('div');
    loaderElement.id = 'loader';
    loaderElement.className = 'loader';
    loaderElement.style.display = 'flex';
    
    const loaderContent = document.createElement('div');
    loaderContent.className = 'loader-content';
    
    const spinner = document.createElement('div');
    spinner.className = 'loader-spinner';
    
    const messageElement = document.createElement('div');
    messageElement.className = 'loader-message';
    messageElement.textContent = message;
    messageElement.id = 'loader-message';
    
    loaderContent.appendChild(spinner);
    loaderContent.appendChild(messageElement);
    
    if (showProgress) {
        const progressContainer = document.createElement('div');
        progressContainer.className = 'loader-progress';
        
        const progressBar = document.createElement('div');
        progressBar.className = 'loader-progress-bar';
        progressBar.id = 'loader-progress-bar';
        
        progressContainer.appendChild(progressBar);
        loaderContent.appendChild(progressContainer);
    }
    
    loaderElement.appendChild(loaderContent);
    document.body.appendChild(loaderElement);
    
    // Add fade-in effect
    setTimeout(() => {
        loaderElement.style.opacity = '1';
    }, 10);
}

function updateLoaderProgress(percent) {
    const progressBar = document.getElementById('loader-progress-bar');
    if (progressBar) {
        progressBar.style.width = `${percent}%`;
    }
}

function updateLoaderMessage(message) {
    const messageElement = document.getElementById('loader-message');
    if (messageElement) {
        messageElement.textContent = message;
    }
}

function hideLoader() {
    const loaderElement = document.getElementById('loader');
    if (loaderElement) {
        // Add fade-out effect
        loaderElement.style.opacity = '0';
        setTimeout(() => {
            loaderElement.remove();
        }, 300);
    }
}

// Crypto utility functions with better error handling
async function deriveKey(password, salt, iterations = DEFAULT_ITERATION_COUNT) {
    return new Promise((resolve, reject) => {
        try {
            setTimeout(() => {
                try {
                    const key = CryptoJS.PBKDF2(password, salt, {
                        keySize: AES_KEY_SIZE / 32, // keySize is in 32-bit words
                        iterations: iterations,
                        hasher: CryptoJS.algo.SHA256
                    });
                    
                    resolve(key);
                } catch (error) {
                    console.error("Key derivation error:", error);
                    reject(error);
                }
            }, 10); // Small timeout to let UI update
        } catch (error) {
            reject(error);
        }
    });
}

async function encrypt(data, key, iv) {
    return new Promise((resolve, reject) => {
        try {
            setTimeout(() => {
                try {
                    // First, stringify and then encrypt all data
                    const jsonData = JSON.stringify(data);
                    
                    // Generate HMAC for data integrity
                    const hmac = CryptoJS.HmacSHA256(jsonData, key).toString();
                    
                    // Encrypt with AES
                    const encrypted = CryptoJS.AES.encrypt(jsonData, key, {
                        iv: CryptoJS.enc.Hex.parse(iv),
                        mode: CryptoJS.mode.CBC,
                        padding: CryptoJS.pad.Pkcs7
                    }).toString();
                    
                    // Return both encrypted data and HMAC
                    resolve({
                        ciphertext: encrypted,
                        hmac: hmac
                    });
                } catch (error) {
                    console.error("Encryption error:", error);
                    reject(error);
                }
            }, 10); // Small timeout to let UI update
        } catch (error) {
            reject(error);
        }
    });
}

async function decrypt(encryptedData, key, iv) {
    return new Promise((resolve, reject) => {
        try {
            setTimeout(() => {
                try {
                    let ciphertext, hmac;
                    
                    // Handle both legacy and new format
                    if (typeof encryptedData === 'object' && encryptedData.ciphertext) {
                        ciphertext = encryptedData.ciphertext;
                        hmac = encryptedData.hmac;
                    } else {
                        // Legacy format - just the ciphertext
                        ciphertext = encryptedData;
                    }
                    
                    // Decrypt the data
                    const bytes = CryptoJS.AES.decrypt(ciphertext, key, {
                        iv: CryptoJS.enc.Hex.parse(iv),
                        mode: CryptoJS.mode.CBC,
                        padding: CryptoJS.pad.Pkcs7
                    });
                    
                    const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
                    if (!decryptedString) {
                        resolve(null);
                        return;
                    }
                    
                    const decryptedData = JSON.parse(decryptedString);
                    
                    // Verify HMAC if it exists in the encrypted data
                    if (hmac) {
                        const computedHmac = CryptoJS.HmacSHA256(decryptedString, key).toString();
                        if (hmac !== computedHmac) {
                            console.error("HMAC verification failed - data may have been tampered with");
                            resolve(null);
                            return;
                        }
                    }
                    
                    resolve(decryptedData);
                } catch (e) {
                    console.error("Decryption error:", e.message);
                    resolve(null);
                }
            }, 10); // Small timeout to let UI update
        } catch (error) {
            reject(error);
        }
    });
}

function generatePassword(length = 20, includeSymbols = true) {
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const special = includeSymbols ? "!@#$%^&*()_+~`|}{[]:;?><,./-=" : "";
    
    let password = "";
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    
    // Ensure we have one of each character type for complexity
    password += lowercase[array[0] % lowercase.length];
    password += uppercase[array[1] % uppercase.length];
    password += numbers[array[2] % numbers.length];
    
    if (includeSymbols) {
        password += special[array[3] % special.length];
    }
    
    // Fill the rest with random characters from all sets
    const allChars = lowercase + uppercase + numbers + special;
    for (let i = (includeSymbols ? 4 : 3); i < length; i++) {
        password += allChars[array[i] % allChars.length];
    }
    
    // Shuffle the password characters
    return password.split('').sort(() => 0.5 - Math.random()).join('');
}

function generateSalt() {
    const array = new Uint8Array(32); // Increased from 16 to 32 bytes
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function generateIV() {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Vault management functions
async function saveVault() {
    if (!masterKey) {
        showNotification('No master key available', 'error');
        return;
    }
    
    try {
        showLoader('Saving vault...');
        
        // Add timestamp for when vault was last modified
        const lastModified = new Date().toISOString();
        
        // Prepare the data to be encrypted
        const data = {
            passwords: vault.passwords,
            version: VAULT_VERSION,
            lastModified: lastModified
        };
        
        updateLoaderMessage('Encrypting data...');
        
        // Encrypt the vault data
        const encryptedResult = await encrypt(data, masterKey, vault.iv);
        
        updateLoaderMessage('Finalizing...');
        
        // Prepare the vault metadata (which will be stored unencrypted)
        const vaultData = {
            encrypted: encryptedResult,
            salt: vault.salt,
            iv: vault.iv,
            iterationCount: vault.iterationCount,
            version: VAULT_VERSION,
            lastAccess: new Date().toISOString()
        };
        
        // Save to local storage
        localStorage.setItem(STORAGE_KEY, JSON.stringify(vaultData));
        
        updateEntryCount();
        hideLoader();
    } catch (error) {
        console.error("Error saving vault:", error);
        hideLoader();
        showNotification('Error saving vault', 'error');
    }
}

function loadVault() {
    const storedData = localStorage.getItem(STORAGE_KEY);
    if (!storedData) return false;
    
    try {
        const parsedData = JSON.parse(storedData);
        vault.salt = parsedData.salt;
        vault.iv = parsedData.iv;
        vault.iterationCount = parsedData.iterationCount || DEFAULT_ITERATION_COUNT;
        vault.version = parsedData.version || '2.0.0';
        vault.lastAccess = parsedData.lastAccess || null;
        return true;
    } catch (e) {
        return false;
    }
}

async function unlockVault(password) {
    if (!vault.salt || !vault.iv) return false;
    
    showLoader('Unlocking vault...', true);
    
    try {
        // Update progress
        updateLoaderProgress(20);
        updateLoaderMessage('Deriving encryption key...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        masterKey = await deriveKey(password, vault.salt, vault.iterationCount);
        
        // Update progress
        updateLoaderProgress(50);
        updateLoaderMessage('Decrypting vault data...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        const storedData = JSON.parse(localStorage.getItem(STORAGE_KEY));
        const decryptedData = await decrypt(storedData.encrypted, masterKey, vault.iv);
        
        updateLoaderProgress(90);
        updateLoaderMessage('Finalizing...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        updateLoaderProgress(100);
        
        if (decryptedData) {
            vault.passwords = decryptedData.passwords || [];
            
            // Update last access time
            storedData.lastAccess = new Date().toISOString();
            localStorage.setItem(STORAGE_KEY, JSON.stringify(storedData));
            
            hideLoader();
            return true;
        } else {
            masterKey = null;
            hideLoader();
            return false;
        }
    } catch (error) {
        console.error("Error unlocking vault:", error);
        masterKey = null;
        hideLoader();
        return false;
    }
}

async function createNewVault(password) {
    try {
        showLoader('Creating vault...', true);
        
        updateLoaderProgress(20);
        updateLoaderMessage('Generating secure keys...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        // Generate salt and IV
        vault.salt = generateSalt();
        vault.iv = generateIV();
        vault.passwords = [];
        
        // Get security level from settings
        let iterationCount = parseInt(localStorage.getItem(SECURITY_LEVEL_STORAGE_KEY) || DEFAULT_ITERATION_COUNT);
        if (isNaN(iterationCount) || iterationCount < DEFAULT_ITERATION_COUNT) {
            iterationCount = DEFAULT_ITERATION_COUNT;
        }
        vault.iterationCount = iterationCount;
        
        updateLoaderProgress(40);
        updateLoaderMessage('Deriving encryption key...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        // Derive the master key
        masterKey = await deriveKey(password, vault.salt, vault.iterationCount);
        
        updateLoaderProgress(80);
        updateLoaderMessage('Saving empty vault...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        // Save the empty vault
        await saveVault();
        
        updateLoaderProgress(100);
        updateLoaderMessage('Vault created successfully!');
        
        // Delay to show success message
        await new Promise(resolve => setTimeout(resolve, 300));
        
        hideLoader();
        return true;
    } catch (error) {
        console.error("Error creating vault:", error);
        showNotification('Error creating vault', 'error');
        hideLoader();
        return false;
    }
}

async function exportVault(exportPassword) {
    showLoader('Preparing export...', true);
    
    try {
        updateLoaderProgress(20);
        updateLoaderMessage('Decrypting vault data...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        const storedData = JSON.parse(localStorage.getItem(STORAGE_KEY));
        const decryptedData = await decrypt(storedData.encrypted, masterKey, vault.iv);
        
        if (!decryptedData) {
            hideLoader();
            showNotification('Failed to decrypt vault for export', 'error');
            return false;
        }
        
        updateLoaderProgress(50);
        updateLoaderMessage('Generating export keys...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 100));
        
        const exportSalt = generateSalt();
        const exportIv = generateIV();
        
        updateLoaderProgress(70);
        updateLoaderMessage('Encrypting export data...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 100));
        
        const exportKey = await deriveKey(exportPassword, exportSalt, DEFAULT_ITERATION_COUNT);
        const encryptedExport = await encrypt(decryptedData, exportKey, exportIv);
        
        updateLoaderProgress(90);
        updateLoaderMessage('Finalizing export data...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 100));
        
        const exportData = {
            encrypted: encryptedExport,
            salt: exportSalt,
            iv: exportIv,
            iterationCount: DEFAULT_ITERATION_COUNT,
            version: VAULT_VERSION
        };
        
        updateLoaderProgress(100);
        updateLoaderMessage('Export completed!');
        
        // Delay to show success message
        await new Promise(resolve => setTimeout(resolve, 300));
        
        hideLoader();
        return JSON.stringify(exportData);
    } catch (error) {
        console.error("Export error:", error);
        showNotification('Export failed', 'error');
        hideLoader();
        return false;
    }
}

async function importVault(exportedText, importPassword) {
    showLoader('Processing import...', true);
    
    try {
        updateLoaderProgress(20);
        updateLoaderMessage('Validating import data...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        let importData;
        try {
            importData = JSON.parse(exportedText);
        } catch (e) {
            hideLoader();
            showNotification('Invalid import data format', 'error');
            return false;
        }
        
        updateLoaderProgress(40);
        updateLoaderMessage('Deriving import key...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        const importKey = await deriveKey(
            importPassword, 
            importData.salt, 
            importData.iterationCount || DEFAULT_ITERATION_COUNT
        );
        
        updateLoaderProgress(70);
        updateLoaderMessage('Decrypting import data...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        const decryptedData = await decrypt(importData.encrypted, importKey, importData.iv);
        
        if (!decryptedData) {
            hideLoader();
            showNotification('Invalid import password or corrupted data', 'error');
            return false;
        }
        
        updateLoaderProgress(90);
        updateLoaderMessage('Merging with existing vault...');
        
        // Delay to show loader
        await new Promise(resolve => setTimeout(resolve, 50));
        
        // Create a map of existing passwords by ID for quick lookup
        const existingPasswordsMap = new Map();
        vault.passwords.forEach(pwd => existingPasswordsMap.set(pwd.id, pwd));
        
        // Add imported passwords, updating existing ones if newer
        if (decryptedData.passwords && Array.isArray(decryptedData.passwords)) {
            decryptedData.passwords.forEach(importedPwd => {
                // Check if password with this ID already exists
                if (existingPasswordsMap.has(importedPwd.id)) {
                    const existingPwd = existingPasswordsMap.get(importedPwd.id);
                    
                    // If imported password is newer, replace the existing one
                    const existingUpdated = new Date(existingPwd.updatedAt || 0);
                    const importedUpdated = new Date(importedPwd.updatedAt || 0);
                    
                    if (importedUpdated > existingUpdated) {
                        existingPasswordsMap.set(importedPwd.id, importedPwd);
                    }
                } else {
                    // New password, just add it
                    existingPasswordsMap.set(importedPwd.id, importedPwd);
                }
            });
        }
        
        // Convert map back to array
        vault.passwords = Array.from(existingPasswordsMap.values());
        
        await saveVault();
        renderPasswordList(vault.passwords);
        
        updateLoaderProgress(100);
        updateLoaderMessage('Import completed!');
        
        // Delay to show success message
        await new Promise(resolve => setTimeout(resolve, 300));
        
        hideLoader();
        showNotification(`Vault imported successfully. Total entries: ${vault.passwords.length}`, 'success');
        return true;
    } catch (e) {
        console.error("Import error:", e);
        hideLoader();
        showNotification('Error during import process', 'error');
        return false;
    }
}

function resetVault() {
    masterKey = null;
    vault = {
        passwords: [],
        salt: null,
        iv: null,
        iterationCount: DEFAULT_ITERATION_COUNT,
        version: VAULT_VERSION,
        lastAccess: null
    };
    
    // Clear auto-logout timer
    clearAutoLogout();
}

// Password handling functions
function showPasswordDetails(id) {
    const password = vault.passwords.find(p => p.id === id);
    if (!password) return;
    
    currentActivePasswordId = id;
    elements.detailTitle.textContent = sanitizeText(password.title);
    elements.detailUsername.textContent = sanitizeText(password.username || '');
    elements.detailPassword.textContent = '••••••••';
    elements.detailPassword.classList.add('masked');
    
    // Update created/modified dates
    if (password.createdAt) {
        elements.detailCreated.textContent = `Created: ${formatDate(password.createdAt)}`;
        elements.detailCreated.style.display = 'block';
    } else {
        elements.detailCreated.style.display = 'none';
    }
    
    if (password.updatedAt) {
        elements.detailUpdated.textContent = `Updated: ${formatDate(password.updatedAt)}`;
        elements.detailUpdated.style.display = 'block';
    } else {
        elements.detailUpdated.style.display = 'none';
    }
    
    if (password.url) {
        elements.urlContainer.style.display = 'flex';
        elements.detailUrl.textContent = sanitizeText(password.url);
        const safeURL = password.url.startsWith('http') ? password.url : `https://${password.url}`;
        elements.detailUrlLink.href = sanitizeText(safeURL);
        elements.detailUrlLink.setAttribute('rel', 'noopener noreferrer');
    } else {
        elements.urlContainer.style.display = 'none';
    }
    
    if (password.notes) {
        elements.notesContainer.style.display = 'flex';
        elements.detailNotes.textContent = sanitizeText(password.notes);
    } else {
        elements.notesContainer.style.display = 'none';
    }
    
    showModal(elements.passwordDetailModal);
}

function addPassword() {
    const title = elements.newTitle.value.trim();
    const username = elements.newUsername.value.trim();
    const password = elements.newPassword.value;
    const url = elements.newUrl.value.trim();
    const notes = elements.newNotes.value.trim();
    
    if (!password) {
        showNotification('Password is required', 'error');
        return false;
    }
    
    const now = new Date().toISOString();
    const id = Date.now().toString();
    vault.passwords.push({
        id,
        title: title || 'Unnamed Entry',
        username: username || '',
        password,
        url,
        notes,
        createdAt: now,
        updatedAt: now
    });
    
    saveVault();
    renderPasswordList(vault.passwords);
    hideModal(elements.addPasswordModal);
    clearForm(elements.addPasswordModal);
    showNotification('Password saved successfully');
    return true;
}

function updatePassword() {
    const id = elements.editId.value;
    const title = elements.editTitle.value.trim();
    const username = elements.editUsername.value.trim();
    const password = elements.editPassword.value;
    const url = elements.editUrl.value.trim();
    const notes = elements.editNotes.value.trim();
    
    if (!password) {
        showNotification('Password is required', 'error');
        return false;
    }
    
    const index = vault.passwords.findIndex(p => p.id === id);
    if (index !== -1) {
        vault.passwords[index] = {
            ...vault.passwords[index],
            title: title || 'Unnamed Entry',
            username: username || '',
            password,
            url,
            notes,
            updatedAt: new Date().toISOString()
        };
        
        saveVault();
        renderPasswordList(vault.passwords);
        hideModal(elements.editPasswordModal);
        showNotification('Password updated successfully');
        return true;
    }
    
    return false;
}

function deletePassword(id) {
    // Create modal for confirmation
    const confirmModal = document.createElement('div');
    confirmModal.className = 'modal';
    confirmModal.id = 'confirm-delete-modal';
    confirmModal.style.display = 'block';
    
    const modalContent = document.createElement('div');
    modalContent.className = 'modal-content';
    
    const modalHeader = document.createElement('div');
    modalHeader.className = 'modal-header';
    
    const title = document.createElement('h3');
    title.textContent = 'CONFIRM DELETE';
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'close-btn';
    closeBtn.innerHTML = '&times;';
    closeBtn.onclick = () => confirmModal.remove();
    
    modalHeader.appendChild(title);
    modalHeader.appendChild(closeBtn);
    
    const message = document.createElement('p');
    message.className = 'modal-description';
    message.textContent = 'Are you sure you want to permanently delete this entry? This action cannot be undone.';
    
    const buttonContainer = document.createElement('div');
    buttonContainer.className = 'modal-buttons';
    
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'secondary-btn';
    cancelBtn.textContent = 'CANCEL';
    cancelBtn.onclick = () => confirmModal.remove();
    
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'danger-btn';
    deleteBtn.textContent = 'DELETE';
    deleteBtn.onclick = () => {
        vault.passwords = vault.passwords.filter(p => p.id !== id);
        saveVault();
        renderPasswordList(vault.passwords);
        hideModal(elements.editPasswordModal);
        confirmModal.remove();
        showNotification('Password deleted successfully');
    };
    
    buttonContainer.appendChild(cancelBtn);
    buttonContainer.appendChild(deleteBtn);
    
    modalContent.appendChild(modalHeader);
    modalContent.appendChild(message);
    modalContent.appendChild(buttonContainer);
    confirmModal.appendChild(modalContent);
    
    document.body.appendChild(confirmModal);
}

function generateAndSetPassword() {
    const length = 20;
    const includeSymbols = true;
    const password = generatePassword(length, includeSymbols);
    elements.newPassword.value = password;
    elements.newPassword.type = 'text';
    elements.newTogglePassword.textContent = 'HIDE';
    
    // Update strength indicator
    const strength = checkPasswordStrength(password);
    elements.newPasswordStrength.textContent = `Strength: ${strength.label}`;
    elements.newPasswordStrength.className = `password-strength strength-${strength.class}`;
    
    // Update meter
    elements.passwordMeterBar.style.width = `${(strength.score / 6) * 100}%`;
    if (strength.class === 'weak') {
        elements.passwordMeterBar.style.backgroundColor = '#ff3333';
    } else if (strength.class === 'medium') {
        elements.passwordMeterBar.style.backgroundColor = '#ffcc00';
    } else {
        elements.passwordMeterBar.style.backgroundColor = '#33ff33';
    }
    
    // Animate the meter
    elements.passwordMeterBar.style.transition = 'width 0.5s ease-in-out, background-color 0.5s ease';
}

// UI functions
function renderPasswordList(passwords, searchTerm = '') {
    showLoader('Loading passwords...');
    
    setTimeout(() => {
        const container = elements.passwordList;
        container.innerHTML = '';
        
        const filteredPasswords = searchTerm 
            ? passwords.filter(p => 
                (p.title && p.title.toLowerCase().includes(searchTerm.toLowerCase())) || 
                (p.username && p.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
                (p.notes && p.notes.toLowerCase().includes(searchTerm.toLowerCase())) ||
                (p.url && p.url.toLowerCase().includes(searchTerm.toLowerCase())))
            : passwords;
        
        // Sort passwords by title
        filteredPasswords.sort((a, b) => {
            return (a.title || '').localeCompare(b.title || '');
        });
        
        if (filteredPasswords.length === 0) {
            const emptyMessage = document.createElement('div');
            emptyMessage.className = 'empty-message';
            emptyMessage.innerHTML = searchTerm 
                ? 'No matching entries found. Try a different search term.'
                : 'No passwords saved yet.<br>Click the + button to add your first password.';
            container.appendChild(emptyMessage);
            
            // Update entry count
            updateEntryCount();
            
            hideLoader();
            return;
        }
        
        // Create item elements with animation delay for staggered appearance
        filteredPasswords.forEach((password, index) => {
            const item = document.createElement('div');
            item.className = 'password-item';
            item.dataset.id = password.id;
            
            // Add animation delay for staggered appearance
            if (animationLevel === 'full') {
                item.style.animationDelay = `${index * 0.05}s`;
            }
            
            const title = document.createElement('h4');
            title.textContent = sanitizeText(password.title || 'Unnamed Entry');
            
            const username = document.createElement('p');
            username.textContent = sanitizeText(password.username || 'No username');
            
            // Add password health indicator
            const health = document.createElement('div');
            health.className = 'password-health';
            const passwordStrength = checkPasswordStrength(password.password);
            
            // Show password last updated date
            let lastUpdated = '';
            if (password.updatedAt) {
                const date = new Date(password.updatedAt);
                lastUpdated = ` · Updated: ${date.toLocaleDateString()}`;
            }
            
            health.innerHTML = `
                <span class="health-icon health-${passwordStrength.class}">●</span>
                <span>${sanitizeText(passwordStrength.label)} password${sanitizeText(lastUpdated)}</span>
            `;
            
            item.appendChild(title);
            item.appendChild(username);
            item.appendChild(health);
            
            item.addEventListener('click', () => {
                showPasswordDetails(password.id);
            });
            
            container.appendChild(item);
        });
        
        // Update entry count
        updateEntryCount();
        
        hideLoader();
    }, 50);
}

// Password strength checker with enhanced algorithm
function checkPasswordStrength(password) {
    if (!password) return { score: 0, label: 'None', class: 'weak' };
    
    let score = 0;
    
    // Length check - more granular
    if (password.length >= 16) score += 3;
    else if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    
    // Character variety checks
    if (/[A-Z]/.test(password)) score += 1; // Uppercase
    if (/[a-z]/.test(password)) score += 1; // Lowercase
    if (/[0-9]/.test(password)) score += 1; // Numbers
    if (/[^A-Za-z0-9]/.test(password)) score += 1; // Special chars
    
    // Pattern checks (reduce score for predictable patterns)
    if (/(.)\1\1/.test(password)) score -= 1; // Repeated characters (e.g., "aaa")
    if (/^(?:password|admin|123456|qwerty|welcome)/i.test(password)) score -= 2; // Common password prefixes
    if (/(?:abcdef|qwerty|12345)/i.test(password)) score -= 1; // Sequential characters
    
    // Normalize score
    if (score < 0) score = 0;
    if (score > 6) score = 6;
    
    // Classify based on score
    if (score >= 5) return { score, label: 'Strong', class: 'strong' };
    if (score >= 3) return { score, label: 'Medium', class: 'medium' };
    return { score, label: 'Weak', class: 'weak' };
}

// Generate a CSRF token with increased entropy
function generateCSRFToken() {
    const array = new Uint8Array(32); // Increased from 16 to 32 bytes
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Verify CSRF token
function verifyCSRFToken(token) {
    const savedToken = localStorage.getItem('csrf_token');
    if (!savedToken) return false;
    
    // Use timing-safe comparison to prevent timing attacks
    let result = 0;
    for (let i = 0; i < token.length; i++) {
        result |= (token.charCodeAt(i) ^ savedToken.charCodeAt(i));
    }
    
    return result === 0;
}

// Matrix background effect
function initMatrixBackground() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    document.getElementById('matrix-background').appendChild(canvas);
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const fontSize = 14;
    const columns = Math.ceil(canvas.width / fontSize);
    const drops = Array(columns).fill(1);
    
    function getRandomChar() {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=%\"'#&_(),.;:?!\\|{}<>[]^~";
        return chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    let lastDraw = 0;
    const fps = 8; // Reduced from 12 to 8 to make it slower
    const interval = 1000 / fps;
    
    function draw(timestamp) {
        if (timestamp - lastDraw < interval) {
            requestAnimationFrame(draw);
            return;
        }
        
        lastDraw = timestamp;
        
        ctx.fillStyle = 'rgba(0, 0, 0, 0.03)'; // Reduced opacity from 0.04 to 0.03 for slower fade
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#0f0';
        ctx.font = `${fontSize}px monospace`;
        
        for (let i = 0; i < drops.length; i++) {
            const text = getRandomChar();
            const x = i * fontSize;
            const y = drops[i] * fontSize;
            
            // Vary brightness to create depth effect
            const green = 100 + Math.floor(Math.random() * 156);
            ctx.fillStyle = `rgba(0, ${green}, 0, ${0.7 + Math.random() * 0.3})`;
            
            ctx.fillText(text, x, y);
            
            if (y > canvas.height && Math.random() > 0.995) { // Reduced drop rate from 0.990 to 0.995
                drops[i] = 0;
            }
            
            drops[i]++;
        }
        
        requestAnimationFrame(draw);
    }
    
    requestAnimationFrame(draw);
    
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const newColumns = Math.ceil(canvas.width / fontSize);
        drops.length = newColumns;
        for (let i = 0; i < newColumns; i++) {
            if (drops[i] === undefined) drops[i] = 1;
        }
    });
}

// Particle background effect
function initParticlesBackground() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    document.getElementById('particles-background').appendChild(canvas);
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const particlesArray = [];
    const numberOfParticles = 70;
    
    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.size = Math.random() * 2 + 1;
            this.speedX = Math.random() * 1 - 0.5;
            this.speedY = Math.random() * 1 - 0.5;
            this.color = `rgba(0, ${150 + Math.floor(Math.random() * 100)}, 0, ${0.1 + Math.random() * 0.3})`;
        }
        
        update() {
            this.x += this.speedX;
            this.y += this.speedY;
            
            if (this.x < 0 || this.x > canvas.width) this.speedX = -this.speedX;
            if (this.y < 0 || this.y > canvas.height) this.speedY = -this.speedY;
        }
        
        draw() {
            ctx.fillStyle = this.color;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }
    
    function init() {
        for (let i = 0; i < numberOfParticles; i++) {
            particlesArray.push(new Particle());
        }
    }
    
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        for (let i = 0; i < particlesArray.length; i++) {
            particlesArray[i].update();
            particlesArray[i].draw();
            
            // Connect particles with lines
            for (let j = i; j < particlesArray.length; j++) {
                const dx = particlesArray[i].x - particlesArray[j].x;
                const dy = particlesArray[i].y - particlesArray[j].y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance < 100) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(0, ${150 + Math.floor(Math.random() * 100)}, 0, ${0.1 - distance/1000})`;
                    ctx.lineWidth = 0.5;
                    ctx.moveTo(particlesArray[i].x, particlesArray[i].y);
                    ctx.lineTo(particlesArray[j].x, particlesArray[j].y);
                    ctx.stroke();
                }
            }
        }
        
        requestAnimationFrame(animate);
    }
    
    init();
    animate();
    
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        particlesArray.length = 0;
        init();
    });
}

// Auto-logout functions with improved timer display
function setupAutoLogout(minutes) {
    let inactivityTime = 0;
    const intervalTime = 1; // seconds (changed from 10 to 1 for more granular timer)
    const maxInactivity = minutes * 60; // convert to seconds
    
    // Reset the timer on user activity
    const resetTimer = () => {
        inactivityTime = 0;
        // Hide the timer if it's showing
        if (elements.logoutTimer.style.display === 'block') {
            elements.logoutTimer.style.display = 'none';
        }
    };
    
    // Add event listeners for user activity
    ['click', 'touchstart', 'mousemove', 'keypress', 'scroll'].forEach(event => {
        document.addEventListener(event, resetTimer);
    });
    
    // Clear any existing interval
    clearAutoLogout();
    
    // Set up the new interval
    window.autoLogoutInterval = setInterval(() => {
        // Only increment timer if user is logged in
        if (elements.vaultScreen.classList.contains('active')) {
            inactivityTime += intervalTime;
            
            // Update the logout timer display
            const timeLeft = maxInactivity - inactivityTime;
            if (timeLeft <= 60 && elements.logoutTimer) { // Show countdown in last minute
                const minutes = Math.floor(timeLeft / 60);
                const seconds = timeLeft % 60;
                elements.logoutTimer.textContent = `Auto-logout in: ${minutes}:${seconds.toString().padStart(2, '0')}`;
                elements.logoutTimer.style.display = 'block';
            }
            
            // Logout when time is up
            if (inactivityTime >= maxInactivity) {
                resetVault();
                elements.masterPassword.value = '';
                showScreen(elements.loginScreen);
                showNotification('Auto-logged out due to inactivity', 'warning');
                elements.logoutTimer.style.display = 'none';
                inactivityTime = 0;
            }
        }
    }, intervalTime * 1000);
}

function clearAutoLogout() {
    if (window.autoLogoutInterval) {
        clearInterval(window.autoLogoutInterval);
    }
    if (elements.logoutTimer) {
        elements.logoutTimer.style.display = 'none';
    }
}

// Apply animation level to the UI
function applyAnimationLevel(level) {
    document.body.classList.remove('minimal-animations', 'no-animations');
    
    switch (level) {
        case 'minimal':
            document.body.classList.add('minimal-animations');
            break;
        case 'none':
            document.body.classList.add('no-animations');
            break;
        // 'full' is default, no class needed
    }
    
    // Store the setting
    localStorage.setItem(ANIMATION_STORAGE_KEY, level);
    animationLevel = level;
}

// Function to change master password
async function changeMasterPassword(currentPassword, newPassword) {
    try {
        showLoader('Verifying current password...', true);
        
        // Verify the current password first
        if (await unlockVault(currentPassword)) {
            updateLoaderProgress(30);
            updateLoaderMessage('Decrypting vault data...');
            
            // Delay to show loader
            await new Promise(resolve => setTimeout(resolve, 50));
            
            // Get the current vault data
            const storedData = JSON.parse(localStorage.getItem(STORAGE_KEY));
            const decryptedData = await decrypt(storedData.encrypted, masterKey, vault.iv);
            
            if (!decryptedData) {
                hideLoader();
                showNotification('Failed to decrypt vault', 'error');
                return false;
            }
            
            updateLoaderProgress(50);
            updateLoaderMessage('Generating new security keys...');
            
            // Delay to show loader
            await new Promise(resolve => setTimeout(resolve, 50));
            
            // Generate new salt
            const newSalt = generateSalt();
            vault.salt = newSalt;
            
            updateLoaderProgress(70);
            updateLoaderMessage('Deriving new encryption key...');
            
            // Delay to show loader
            await new Promise(resolve => setTimeout(resolve, 50));
            
            // Derive new master key
            masterKey = await deriveKey(newPassword, newSalt, vault.iterationCount);
            
            updateLoaderProgress(90);
            updateLoaderMessage('Saving vault with new password...');
            
            // Delay to show loader
            await new Promise(resolve => setTimeout(resolve, 50));
            
            // Save the vault with the new key
            await saveVault();
            
            updateLoaderProgress(100);
            updateLoaderMessage('Password changed successfully!');
            
            // Delay to show success message
            await new Promise(resolve => setTimeout(resolve, 300));
            
            hideLoader();
            showNotification('Master password changed successfully', 'success');
            return true;
        } else {
            hideLoader();
            showNotification('Current password is incorrect', 'error');
            return false;
        }
    } catch (error) {
        console.error("Error changing master password:", error);
        hideLoader();
        showNotification('Error changing password', 'error');
        return false;
    }
}

// Event listeners with enhanced functionality
function setupEventListeners() {
    // Login screen
    elements.loginBtn.addEventListener('click', async () => {
        const password = elements.masterPassword.value;
        if (!password) {
            showNotification('Please enter a password', 'warning');
            elements.masterPassword.focus();
            return;
        }
        
        if (loadVault()) {
            const success = await unlockVault(password);
            if (success) {
                showScreen(elements.vaultScreen);
                renderPasswordList(vault.passwords);
                showNotification('Vault unlocked successfully', 'success');
                elements.searchInput.focus();
            } else {
                showNotification('Incorrect password', 'error');
                elements.masterPassword.value = '';
                elements.masterPassword.focus();
            }
        } else {
            showNotification('No vault found. Create a new one.', 'warning');
        }
    });
    
    elements.createVaultBtn.addEventListener('click', async () => {
        const password = elements.masterPassword.value;
        if (!password) {
            showNotification('Please enter a password', 'warning');
            elements.masterPassword.focus();
            return;
        }
        
        // Check password strength
        const strength = checkPasswordStrength(password);
        if (strength.score < 3) {
            const confirm = window.confirm('Your master password is weak. It is strongly recommended to use a stronger password. Continue anyway?');
            if (!confirm) {
                return;
            }
        }
        
        const success = await createNewVault(password);
        if (success) {
            showScreen(elements.vaultScreen);
            renderPasswordList(vault.passwords);
            showNotification('New vault created successfully', 'success');
            elements.searchInput.focus();
        }
    });
    
    elements.masterPassword.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            elements.loginBtn.click();
        }
    });
    
    // Password visibility toggles
    if (elements.newTogglePassword) {
        elements.newTogglePassword.addEventListener('click', () => {
            togglePasswordVisibility(elements.newPassword, elements.newTogglePassword);
        });
    }
    
    if (elements.editTogglePassword) {
        elements.editTogglePassword.addEventListener('click', () => {
            togglePasswordVisibility(elements.editPassword, elements.editTogglePassword);
        });
    }
    
    // Password strength indicators
    if (elements.newPassword) {
        elements.newPassword.addEventListener('input', (e) => {
            const password = e.target.value;
            const strength = checkPasswordStrength(password);
            
            elements.newPasswordStrength.textContent = `Strength: ${strength.label}`;
            elements.newPasswordStrength.className = `password-strength strength-${strength.class}`;
            
            // Update meter
            elements.passwordMeterBar.style.width = `${(strength.score / 6) * 100}%`;
            if (strength.class === 'weak') {
                elements.passwordMeterBar.style.backgroundColor = '#ff3333';
            } else if (strength.class === 'medium') {
                elements.passwordMeterBar.style.backgroundColor = '#ffcc00';
            } else {
                elements.passwordMeterBar.style.backgroundColor = '#33ff33';
            }
        });
    }
    
    if (elements.newMaster) {
        elements.newMaster.addEventListener('input', (e) => {
            const password = e.target.value;
            const strength = checkPasswordStrength(password);
            
            elements.masterPasswordStrength.textContent = `Strength: ${strength.label}`;
            elements.masterPasswordStrength.className = `password-strength strength-${strength.class}`;
            
            // Update meter
            elements.masterPasswordMeterBar.style.width = `${(strength.score / 6) * 100}%`;
            if (strength.class === 'weak') {
                elements.masterPasswordMeterBar.style.backgroundColor = '#ff3333';
            } else if (strength.class === 'medium') {
                elements.masterPasswordMeterBar.style.backgroundColor = '#ffcc00';
            } else {
                elements.masterPasswordMeterBar.style.backgroundColor = '#33ff33';
            }
        });
    }
    
    // Vault screen
    elements.addBtn.addEventListener('click', () => {
        clearForm(elements.addPasswordModal);
        showModal(elements.addPasswordModal);
        setTimeout(() => elements.newTitle.focus(), 100);
    });
    
    elements.exportBtn.addEventListener('click', () => {
        clearForm(elements.exportModal);
        document.querySelector('.export-text-area').style.display = 'none';
        elements.confirmExportBtn.style.display = 'block';
        showModal(elements.exportModal);
        setTimeout(() => elements.exportPassword.focus(), 100);
    });
    
    elements.importBtn.addEventListener('click', () => {
        clearForm(elements.importModal);
        showModal(elements.importModal);
        setTimeout(() => elements.importText.focus(), 100);
    });
    
    elements.logoutBtn.addEventListener('click', () => {
        resetVault();
        elements.masterPassword.value = '';
        showScreen(elements.loginScreen);
        showNotification('Logged out successfully', 'success');
    });
    
    elements.searchInput.addEventListener('input', (e) => {
        renderPasswordList(vault.passwords, e.target.value);
    });
    
    // Add password modal
    elements.generatePasswordBtn.addEventListener('click', generateAndSetPassword);
    
    elements.savePasswordBtn.addEventListener('click', () => {
        if (addPassword()) {
            showNotification('Password saved successfully', 'success');
        }
    });
    
    elements.cancelAddBtn.addEventListener('click', () => {
        hideModal(elements.addPasswordModal);
    });
    
    // Edit password modal
    elements.updatePasswordBtn.addEventListener('click', () => {
        if (updatePassword()) {
            showNotification('Password updated successfully', 'success');
        }
    });
    
    elements.deletePasswordBtn.addEventListener('click', () => {
        deletePassword(elements.editId.value);
    });
    
    elements.cancelEditBtn.addEventListener('click', () => {
        hideModal(elements.editPasswordModal);
    });
    
    // Password detail modal
    elements.closeDetailBtn.addEventListener('click', () => {
        hideModal(elements.passwordDetailModal);
    });
    
    elements.editEntryBtn.addEventListener('click', () => {
        const password = vault.passwords.find(p => p.id === currentActivePasswordId);
        if (!password) return;
        
        elements.editId.value = password.id;
        elements.editTitle.value = password.title;
        elements.editUsername.value = password.username || '';
        elements.editPassword.value = password.password;
        elements.editUrl.value = password.url || '';
        elements.editNotes.value = password.notes || '';
        
        hideModal(elements.passwordDetailModal);
        showModal(elements.editPasswordModal);
        setTimeout(() => elements.editTitle.focus(), 100);
    });
    
    // Toggle password visibility
    document.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const field = btn.dataset.field;
            const element = document.getElementById(`detail-${field}`);
            const password = vault.passwords.find(p => p.id === currentActivePasswordId);
            
            if (element.classList.contains('masked')) {
                element.textContent = password[field];
                element.classList.remove('masked');
                btn.textContent = 'HIDE';
            } else {
                element.textContent = '••••••••';
                element.classList.add('masked');
                btn.textContent = 'SHOW';
            }
        });
    });
    
    // Copy to clipboard
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const field = btn.dataset.field;
            const password = vault.passwords.find(p => p.id === currentActivePasswordId);
            
            if (navigator.clipboard) {
                navigator.clipboard.writeText(password[field])
                    .then(() => {
                        showNotification(`${field.charAt(0).toUpperCase() + field.slice(1)} copied to clipboard`, 'success');
                    })
                    .catch(() => {
                        showNotification('Failed to copy to clipboard', 'error');
                    });
            } else {
                const textarea = document.createElement('textarea');
                textarea.value = password[field];
                textarea.style.position = 'fixed';
                document.body.appendChild(textarea);
                textarea.focus();
                textarea.select();
                
                try {
                    const successful = document.execCommand('copy');
                    const message = successful 
                        ? `${field.charAt(0).toUpperCase() + field.slice(1)} copied to clipboard` 
                        : 'Failed to copy to clipboard';
                    showNotification(message, successful ? 'success' : 'error');
                } catch (err) {
                    showNotification('Failed to copy to clipboard', 'error');
                }
                
                document.body.removeChild(textarea);
            }
        });
    });
    
    // Export modal
    elements.confirmExportBtn.addEventListener('click', async () => {
        const exportPassword = elements.exportPassword.value;
        const confirmPassword = elements.confirmExportPassword.value;
        
        if (!exportPassword) {
            showNotification('Please enter an export password', 'warning');
            elements.exportPassword.focus();
            return;
        }
        
        if (exportPassword !== confirmPassword) {
            showNotification('Passwords do not match', 'error');
            elements.confirmExportPassword.focus();
            return;
        }
        
        const exportedData = await exportVault(exportPassword);
        if (exportedData) {
            // Show the text area with the exported data
            document.querySelector('.export-text-area').style.display = 'block';
            document.getElementById('export-text').value = exportedData;
            elements.confirmExportBtn.style.display = 'none';
            showNotification('Vault data ready for export', 'success');
            
            // Select the exported text for easy copying
            setTimeout(() => {
                elements.exportText.select();
                elements.exportText.focus();
            }, 100);
        } else {
            showNotification('Failed to export vault', 'error');
        }
    });

    elements.copyExportBtn.addEventListener('click', () => {
        const exportText = elements.exportText;
        exportText.select();
        
        if (navigator.clipboard) {
            navigator.clipboard.writeText(exportText.value)
                .then(() => {
                    showNotification('Export data copied to clipboard', 'success');
                })
                .catch(err => {
                    showNotification('Could not copy text: ' + err.message, 'error');
                });
        } else {
            try {
                document.execCommand('copy');
                showNotification('Export data copied to clipboard', 'success');
            } catch (err) {
                showNotification('Could not copy text: ' + err.message, 'error');
            }
        }
    });

    elements.cancelExportBtn.addEventListener('click', () => {
        hideModal(elements.exportModal);
        // Reset the export form
        document.querySelector('.export-text-area').style.display = 'none';
        elements.exportText.value = '';
        elements.confirmExportBtn.style.display = 'block';
    });
    
    // Import modal
    elements.confirmImportBtn.addEventListener('click', async () => {
        const importText = elements.importText.value.trim();
        const importPassword = elements.importPassword.value;
        
        if (!importText) {
            showNotification('Please paste the exported vault data', 'warning');
            elements.importText.focus();
            return;
        }
        
        if (!importPassword) {
            showNotification('Please enter the import password', 'warning');
            elements.importPassword.focus();
            return;
        }
        
        const result = await importVault(importText, importPassword);
        if (result) {
            hideModal(elements.importModal);
        }
    });
    
    elements.cancelImportBtn.addEventListener('click', () => {
        hideModal(elements.importModal);
        clearForm(elements.importModal);
    });
    
    // Settings button
    if (elements.settingsBtn) {
        elements.settingsBtn.addEventListener('click', () => {
            showModal(elements.settingsModal);
            
            // Set current values
            if (elements.securityLevel) {
                const currentLevel = localStorage.getItem(SECURITY_LEVEL_STORAGE_KEY) || DEFAULT_ITERATION_COUNT.toString();
                elements.securityLevel.value = currentLevel;
            }
            
            if (elements.animationLevel) {
                const currentLevel = localStorage.getItem(ANIMATION_STORAGE_KEY) || 'full';
                elements.animationLevel.value = currentLevel;
            }
        });
    }
    
    // Close settings
    if (elements.closeSettingsBtn) {
        elements.closeSettingsBtn.addEventListener('click', () => {
            hideModal(elements.settingsModal);
        });
    }
    
    // Security level setting
    if (elements.securityLevel) {
        elements.securityLevel.addEventListener('change', (e) => {
            const iterationCount = e.target.value;
            localStorage.setItem(SECURITY_LEVEL_STORAGE_KEY, iterationCount);
            showNotification(`Security level updated. Will apply on next login.`, 'success');
        });
    }
    
    // Animation level setting
    if (elements.animationLevel) {
        elements.animationLevel.addEventListener('change', (e) => {
            const level = e.target.value;
            applyAnimationLevel(level);
            showNotification(`Animation level set to ${level}`, 'success');
        });
    }
    
    // Clear all data
    if (elements.clearDataBtn) {
        elements.clearDataBtn.addEventListener('click', () => {
            // Create modal for confirmation
            const confirmModal = document.createElement('div');
            confirmModal.className = 'modal';
            confirmModal.style.display = 'block';
            
            const modalContent = document.createElement('div');
            modalContent.className = 'modal-content';
            
            const modalHeader = document.createElement('div');
            modalHeader.className = 'modal-header';
            
            const title = document.createElement('h3');
            title.textContent = 'CONFIRM DATA DELETION';
            
            const closeBtn = document.createElement('button');
            closeBtn.className = 'close-btn';
            closeBtn.innerHTML = '&times;';
            closeBtn.onclick = () => confirmModal.remove();
            
            modalHeader.appendChild(title);
            modalHeader.appendChild(closeBtn);
            
            const message = document.createElement('p');
            message.className = 'modal-description';
            message.innerHTML = '<strong>WARNING:</strong> This will permanently delete all your saved passwords and vault data. This action cannot be undone.<br><br>Type "DELETE" below to confirm:';
            
            const confirmInput = document.createElement('input');
            confirmInput.type = 'text';
            confirmInput.placeholder = 'Type DELETE to confirm';
            confirmInput.className = 'input-container';
            
            const buttonContainer = document.createElement('div');
            buttonContainer.className = 'modal-buttons';
            
            const cancelBtn = document.createElement('button');
            cancelBtn.className = 'secondary-btn';
            cancelBtn.textContent = 'CANCEL';
            cancelBtn.onclick = () => confirmModal.remove();
            
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'danger-btn';
            deleteBtn.textContent = 'DELETE ALL DATA';
            deleteBtn.disabled = true;
            
            confirmInput.addEventListener('input', (e) => {
                deleteBtn.disabled = e.target.value !== 'DELETE';
            });
            
            deleteBtn.onclick = () => {
                if (confirmInput.value === 'DELETE') {
                    localStorage.clear();
                    resetVault();
                    showScreen(elements.loginScreen);
                    confirmModal.remove();
                    showNotification('All data has been permanently deleted', 'success');
                }
            };
            
            buttonContainer.appendChild(cancelBtn);
            buttonContainer.appendChild(deleteBtn);
            
            modalContent.appendChild(modalHeader);
            modalContent.appendChild(message);
            modalContent.appendChild(confirmInput);
            modalContent.appendChild(buttonContainer);
            confirmModal.appendChild(modalContent);
            
            document.body.appendChild(confirmModal);
        });
    }
    
    // Auto-logout setting
    if (elements.autoLogout) {
        elements.autoLogout.addEventListener('change', (e) => {
            const minutes = parseInt(e.target.value);
            localStorage.setItem('auto_logout_minutes', minutes);
            
            if (minutes > 0) {
                setupAutoLogout(minutes);
                showNotification(`Auto-logout set to ${minutes} minute(s)`, 'success');
            } else {
                clearAutoLogout();
                showNotification('Auto-logout disabled', 'success');
            }
        });
        
        // Load saved auto-logout setting
        const savedMinutes = localStorage.getItem('auto_logout_minutes');
        if (savedMinutes) {
            elements.autoLogout.value = savedMinutes;
            if (parseInt(savedMinutes) > 0) {
                setupAutoLogout(parseInt(savedMinutes));
            }
        }
    }
    
    // Change master password
    if (elements.changeMasterBtn) {
        elements.changeMasterBtn.addEventListener('click', () => {
            hideModal(elements.settingsModal);
            clearForm(elements.changeMasterModal);
            showModal(elements.changeMasterModal);
            setTimeout(() => elements.currentMaster.focus(), 100);
        });
    }
    
    if (elements.confirmChangeMasterBtn) {
        elements.confirmChangeMasterBtn.addEventListener('click', async () => {
            const currentPassword = elements.currentMaster.value;
            const newPassword = elements.newMaster.value;
            const confirmPassword = elements.confirmNewMaster.value;
            
            if (!currentPassword || !newPassword || !confirmPassword) {
                showNotification('All fields are required', 'warning');
                return;
            }
            
            if (newPassword !== confirmPassword) {
                showNotification('New passwords do not match', 'error');
                return;
            }
            
            const strength = checkPasswordStrength(newPassword);
            if (strength.score < 3) {
                const confirm = window.confirm('Your new password is weak. Are you sure you want to use it?');
                if (!confirm) {
                    return;
                }
            }
            
            const success = await changeMasterPassword(currentPassword, newPassword);
            if (success) {
                hideModal(elements.changeMasterModal);
            }
        });
    }
    
    if (elements.cancelChangeMasterBtn) {
        elements.cancelChangeMasterBtn.addEventListener('click', () => {
            hideModal(elements.changeMasterModal);
        });
    }
}

// Initialize the application
function init() {
    // Load animation preferences
    animationLevel = localStorage.getItem(ANIMATION_STORAGE_KEY) || 'full';
    applyAnimationLevel(animationLevel);
    
    // Initialize backgrounds
    initMatrixBackground();
    if (animationLevel === 'full') {
        initParticlesBackground();
    }
    
    setupEventListeners();
    
    // Set Content Security Policy programmatically
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self';";
    document.head.appendChild(meta);
    
    // Generate initial CSRF token
    localStorage.setItem('csrf_token', generateCSRFToken());
    
    // Check if there's a vault already
    if (loadVault()) {
        showScreen(elements.loginScreen);
    } else {
        showScreen(elements.loginScreen);
        elements.createVaultBtn.style.display = 'block';
    }
}

// Start the app when DOM is loaded
document.addEventListener('DOMContentLoaded', init);