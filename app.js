// Matrix Vault Pro - Secure Password Manager
// Version 3.0.0 - Enhanced Security with Modern Cryptography
// Uses: TweetNaCl.js (ChaCha20-Poly1305), Argon2, and Web Crypto API

// ============================================================================
// SECURITY CONSTANTS
// ============================================================================
const STORAGE_KEY = 'matrix_vault_data';
const VAULT_VERSION = '3.0.0';

// Argon2 Parameters (recommended by OWASP 2023)
const ARGON2_PARAMS = {
    time: 2,           // iterations
    mem: 65540,        // 64MB memory
    parallelism: 1,
    hashLen: 32        // 256 bits
};

const ENCRYPTION_ALGORITHM = 'ChaCha20-Poly1305';
const ANIMATION_STORAGE_KEY = 'animation_level';

// Rate Limiting for Login Attempts
const RATE_LIMIT_CONFIG = {
    maxAttempts: 5,
    baseDelayMs: 1000,
    maxDelayMs: 300000  // 5 minutes
};

// ============================================================================
// APP STATE
// ============================================================================
let vault = {
    passwords: [],
    salt: null,
    nonce: null,
    version: VAULT_VERSION,
    lastAccess: null
};

let masterKey = null;
let currentActivePasswordId = null;
let animationLevel = localStorage.getItem(ANIMATION_STORAGE_KEY) || 'full';

// Rate limiting state
let loginAttempts = {
    count: 0,
    lastFailedTime: 0,
    blocked: false,
    unblockTime: 0
};

// ============================================================================
// DOM ELEMENTS
// ============================================================================
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
    rateLimitWarning: document.getElementById('rate-limit-warning'),
    waitTime: document.getElementById('wait-time'),
    
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

// ============================================================================
// SECURITY UTILITIES
// ============================================================================

/**
 * Generate cryptographically secure random bytes
 */
function generateRandomBytes(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
}

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Timing-safe string comparison
 * Prevents timing attacks by always comparing all characters
 */
function constantTimeEquals(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
        return false;
    }
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

/**
 * Derive encryption key using Argon2id (modern, OWASP-recommended)
 * Falls back to Web Crypto API for broader compatibility
 */
async function deriveKeyArgon2(password, salt) {
    return new Promise(async (resolve, reject) => {
        try {
            // Check if Argon2 library is available
            if (typeof argon2 !== 'undefined') {
                showLoader('Deriving encryption key with Argon2...', true);
                updateLoaderProgress(50);
                
                const result = await argon2.hash({
                    pass: password,
                    salt: salt,
                    time: ARGON2_PARAMS.time,
                    mem: ARGON2_PARAMS.mem,
                    parallelism: ARGON2_PARAMS.parallelism,
                    hashLen: ARGON2_PARAMS.hashLen,
                    type: argon2.ArgonType.Argon2id
                });
                
                updateLoaderProgress(100);
                
                // Use the hash as the key
                const keyBytes = hexToBytes(result.hashHex.substring(0, 64)); // 32 bytes
                resolve(keyBytes);
            } else {
                throw new Error('Argon2 library not loaded');
            }
        } catch (error) {
            console.error("Argon2 key derivation error:", error);
            // Fallback to PBKDF2 with increased iterations
            try {
                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(password),
                    { name: 'PBKDF2' },
                    false,
                    ['deriveBits']
                );
                
                const derivedBits = await crypto.subtle.deriveBits(
                    {
                        name: 'PBKDF2',
                        hash: 'SHA-256',
                        salt: salt,
                        iterations: 600000  // OWASP 2023 minimum
                    },
                    keyMaterial,
                    256  // 32 bytes
                );
                
                resolve(new Uint8Array(derivedBits));
            } catch (fallbackError) {
                reject(fallbackError);
            }
        }
    });
}

/**
 * Encrypt data using ChaCha20-Poly1305 (modern AEAD)
 * Provides both confidentiality AND authentication
 */
async function encryptChaCha20(plaintext, key, nonce) {
    return new Promise((resolve, reject) => {
        try {
            if (typeof nacl === 'undefined') {
                throw new Error('TweetNaCl.js library not loaded');
            }
            
            // TweetNaCl uses 32-byte keys and 24-byte nonces (Poly1305)
            if (key.length !== 32 || nonce.length !== 24) {
                throw new Error('Invalid key or nonce length');
            }
            
            const plaintextArray = new TextEncoder().encode(plaintext);
            
            // Encrypt and authenticate in one operation
            const ciphertext = nacl.secretbox(plaintextArray, nonce, key);
            
            if (!ciphertext) {
                throw new Error('Encryption failed');
            }
            
            resolve(ciphertext);
        } catch (error) {
            console.error("Encryption error:", error);
            reject(error);
        }
    });
}

/**
 * Decrypt data using ChaCha20-Poly1305
 * Verifies authentication tag automatically
 */
async function decryptChaCha20(ciphertext, key, nonce) {
    return new Promise((resolve, reject) => {
        try {
            if (typeof nacl === 'undefined') {
                throw new Error('TweetNaCl.js library not loaded');
            }
            
            // Verify key and nonce lengths
            if (key.length !== 32 || nonce.length !== 24) {
                throw new Error('Invalid key or nonce length');
            }
            
            // Decrypt and verify authentication in one operation
            const plaintext = nacl.secretbox.open(ciphertext, nonce, key);
            
            if (!plaintext) {
                // Authentication failed - data was tampered with
                console.error("Authentication failed - ciphertext may have been tampered with");
                resolve(null);
                return;
            }
            
            const plaintextString = new TextDecoder().decode(plaintext);
            resolve(plaintextString);
        } catch (error) {
            console.error("Decryption error:", error);
            resolve(null);
        }
    });
}

/**
 * Sanitize text to prevent XSS attacks
 */
function sanitizeText(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Validate URL to prevent JavaScript protocol injection
 */
function validateAndSanitizeURL(url) {
    if (!url) return null;
    
    try {
        const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
        
        // Only allow http and https protocols
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            console.warn('Invalid URL protocol:', parsed.protocol);
            return null;
        }
        
        return parsed.href;
    } catch (error) {
        console.warn('Invalid URL:', error);
        return null;
    }
}

/**
 * Format date to readable format
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString();
}

/**
 * Download file helper
 */
function downloadFile(content, filename, mimeType = 'application/octet-stream') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// ============================================================================
// RATE LIMITING
// ============================================================================

/**
 * Check if login attempts are rate limited
 */
function checkRateLimit() {
    const now = Date.now();
    
    // Reset counter if enough time has passed
    if (now - loginAttempts.lastFailedTime > RATE_LIMIT_CONFIG.maxDelayMs) {
        loginAttempts.count = 0;
        loginAttempts.blocked = false;
        elements.rateLimitWarning.style.display = 'none';
        return true;
    }
    
    if (loginAttempts.count >= RATE_LIMIT_CONFIG.maxAttempts) {
        // Calculate exponential backoff
        const delayMs = Math.min(
            RATE_LIMIT_CONFIG.baseDelayMs * Math.pow(2, loginAttempts.count - RATE_LIMIT_CONFIG.maxAttempts),
            RATE_LIMIT_CONFIG.maxDelayMs
        );
        
        const timeSinceLastFail = now - loginAttempts.lastFailedTime;
        
        if (timeSinceLastFail < delayMs) {
            loginAttempts.blocked = true;
            loginAttempts.unblockTime = loginAttempts.lastFailedTime + delayMs;
            return false;
        } else {
            loginAttempts.count = 0;
            loginAttempts.blocked = false;
            elements.rateLimitWarning.style.display = 'none';
            return true;
        }
    }
    
    return true;
}

/**
 * Update rate limit warning display
 */
function updateRateLimitDisplay() {
    if (loginAttempts.blocked) {
        const now = Date.now();
        const timeLeft = Math.ceil((loginAttempts.unblockTime - now) / 1000);
        
        if (timeLeft > 0) {
            elements.rateLimitWarning.style.display = 'block';
            elements.waitTime.textContent = timeLeft;
            elements.loginBtn.disabled = true;
            
            setTimeout(updateRateLimitDisplay, 1000);
        } else {
            loginAttempts.blocked = false;
            elements.rateLimitWarning.style.display = 'none';
            elements.loginBtn.disabled = false;
        }
    }
}

/**
 * Record failed login attempt
 */
function recordFailedAttempt() {
    loginAttempts.count++;
    loginAttempts.lastFailedTime = Date.now();
    
    if (loginAttempts.count >= RATE_LIMIT_CONFIG.maxAttempts) {
        loginAttempts.blocked = true;
        updateRateLimitDisplay();
    }
}

/**
 * Reset login attempts on successful login
 */
function resetLoginAttempts() {
    loginAttempts.count = 0;
    loginAttempts.blocked = false;
    elements.rateLimitWarning.style.display = 'none';
}

// ============================================================================
// PASSWORD GENERATION
// ============================================================================

/**
 * Generate cryptographically secure random password
 * Using Fisher-Yates shuffle with crypto.getRandomValues()
 */
function generatePassword(length = 20, includeSymbols = true) {
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const special = includeSymbols ? "!@#$%^&*()_+~`|}{[]:;?><,./-=" : "";
    
    let password = "";
    const randomBytes = generateRandomBytes(length);
    
    // Ensure we have one of each character type for complexity
    password += lowercase[randomBytes[0] % lowercase.length];
    password += uppercase[randomBytes[1] % uppercase.length];
    password += numbers[randomBytes[2] % numbers.length];
    
    if (includeSymbols) {
        password += special[randomBytes[3] % special.length];
    }
    
    // Fill the rest with random characters from all sets
    const allChars = lowercase + uppercase + numbers + special;
    for (let i = (includeSymbols ? 4 : 3); i < length; i++) {
        password += allChars[randomBytes[i] % allChars.length];
    }
    
    // Secure Fisher-Yates shuffle
    return secureShuffleArray(password.split('')).join('');
}

/**
 * Secure Fisher-Yates shuffle using crypto.getRandomValues()
 */
function secureShuffleArray(array) {
    const arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
        const randomBytes = generateRandomBytes(4);
        const randomValue = new DataView(randomBytes.buffer).getUint32(0, true);
        const j = randomValue % (i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

// ============================================================================
// VAULT OPERATIONS
// ============================================================================

/**
 * Save vault to localStorage with ChaCha20-Poly1305 encryption
 */
async function saveVault() {
    if (!masterKey) {
        showNotification('No master key available', 'error');
        return;
    }
    
    try {
        showLoader('Saving vault...', true);
        
        const lastModified = new Date().toISOString();
        
        // Prepare data to encrypt
        const data = {
            passwords: vault.passwords,
            version: VAULT_VERSION,
            lastModified: lastModified
        };
        
        updateLoaderMessage('Encrypting data with ChaCha20-Poly1305...');
        
        // Generate fresh nonce for this encryption
        const nonce = generateRandomBytes(24); // 192-bit nonce for ChaCha20-Poly1305
        
        // Encrypt the vault data
        const plaintext = JSON.stringify(data);
        const ciphertext = await encryptChaCha20(plaintext, masterKey, nonce);
        
        updateLoaderMessage('Finalizing...');
        
        // Prepare vault metadata
        const vaultData = {
            encrypted: bytesToHex(ciphertext),
            nonce: bytesToHex(nonce),
            salt: vault.salt,
            version: VAULT_VERSION,
            algorithm: ENCRYPTION_ALGORITHM,
            lastAccess: new Date().toISOString()
        };
        
        // Save to localStorage
        localStorage.setItem(STORAGE_KEY, JSON.stringify(vaultData));
        
        updateEntryCount();
        hideLoader();
    } catch (error) {
        console.error("Error saving vault:", error);
        hideLoader();
        showNotification('Error saving vault', 'error');
    }
}

/**
 * Load vault metadata from localStorage
 */
function loadVault() {
    const storedData = localStorage.getItem(STORAGE_KEY);
    if (!storedData) return false;
    
    try {
        const parsedData = JSON.parse(storedData);
        vault.salt = parsedData.salt;
        vault.nonce = parsedData.nonce;
        vault.version = parsedData.version || VAULT_VERSION;
        vault.lastAccess = parsedData.lastAccess || null;
        return true;
    } catch (e) {
        console.error("Error loading vault:", e);
        return false;
    }
}

/**
 * Unlock vault using master password
 */
async function unlockVault(password) {
    if (!vault.salt || !vault.nonce) return false;
    
    showLoader('Unlocking vault...', true);
    
    try {
        updateLoaderProgress(20);
        updateLoaderMessage('Deriving encryption key...');
        
        // Derive key using Argon2 or PBKDF2
        const salt = hexToBytes(vault.salt);
        masterKey = await deriveKeyArgon2(password, salt);
        
        updateLoaderProgress(50);
        updateLoaderMessage('Decrypting vault data...');
        
        const storedData = JSON.parse(localStorage.getItem(STORAGE_KEY));
        const nonce = hexToBytes(storedData.nonce);
        const ciphertext = hexToBytes(storedData.encrypted);
        
        const decryptedString = await decryptChaCha20(ciphertext, masterKey, nonce);
        
        updateLoaderProgress(90);
        updateLoaderMessage('Finalizing...');
        
        if (!decryptedString) {
            masterKey = null;
            hideLoader();
            showNotification('Failed to decrypt vault - check your password', 'error');
            return false;
        }
        
        const decryptedData = JSON.parse(decryptedString);
        vault.passwords = decryptedData.passwords || [];
        
        // Update last access time
        storedData.lastAccess = new Date().toISOString();
        localStorage.setItem(STORAGE_KEY, JSON.stringify(storedData));
        
        updateLoaderProgress(100);
        
        hideLoader();
        resetLoginAttempts();
        return true;
    } catch (error) {
        console.error("Error unlocking vault:", error);
        masterKey = null;
        hideLoader();
        return false;
    }
}

/**
 * Create new vault with master password
 */
async function createNewVault(password) {
    try {
        showLoader('Creating vault...', true);
        
        updateLoaderProgress(20);
        updateLoaderMessage('Generating secure keys...');
        
        // Generate salt and nonce for new vault
        vault.salt = bytesToHex(generateRandomBytes(32)); // 256-bit salt
        vault.nonce = bytesToHex(generateRandomBytes(24)); // 192-bit nonce
        vault.passwords = [];
        
        updateLoaderProgress(40);
        updateLoaderMessage('Deriving encryption key with Argon2...');
        
        // Derive the master key
        masterKey = await deriveKeyArgon2(password, hexToBytes(vault.salt));
        
        updateLoaderProgress(80);
        updateLoaderMessage('Saving empty vault...');
        
        // Save the empty vault
        await saveVault();
        
        updateLoaderProgress(100);
        updateLoaderMessage('Vault created successfully!');
        
        await new Promise(resolve => setTimeout(resolve, 300));
        
        hideLoader();
        resetLoginAttempts();
        return true;
    } catch (error) {
        console.error("Error creating vault:", error);
        showNotification('Error creating vault', 'error');
        hideLoader();
        return false;
    }
}

/**
 * Export vault with secondary encryption
 */
async function exportVault(exportPassword) {
    showLoader('Preparing export...', true);
    
    try {
        updateLoaderProgress(20);
        updateLoaderMessage('Decrypting vault data...');
        
        const storedData = JSON.parse(localStorage.getItem(STORAGE_KEY));
        const nonce = hexToBytes(storedData.nonce);
        const ciphertext = hexToBytes(storedData.encrypted);
        
        const decryptedString = await decryptChaCha20(ciphertext, masterKey, nonce);
        
        if (!decryptedString) {
            hideLoader();
            showNotification('Failed to decrypt vault for export', 'error');
            return false;
        }
        
        const decryptedData = JSON.parse(decryptedString);
        
        updateLoaderProgress(50);
        updateLoaderMessage('Generating export keys...');
        
        const exportSalt = generateRandomBytes(32);
        const exportNonce = generateRandomBytes(24);
        
        updateLoaderProgress(70);
        updateLoaderMessage('Encrypting export data...');
        
        const exportKey = await deriveKeyArgon2(exportPassword, exportSalt);
        const exportPlaintext = JSON.stringify(decryptedData);
        const encryptedExport = await encryptChaCha20(exportPlaintext, exportKey, exportNonce);
        
        updateLoaderProgress(90);
        updateLoaderMessage('Finalizing export data...');
        
        const exportData = {
            encrypted: bytesToHex(encryptedExport),
            nonce: bytesToHex(exportNonce),
            salt: bytesToHex(exportSalt),
            version: VAULT_VERSION,
            algorithm: ENCRYPTION_ALGORITHM
        };
        
        updateLoaderProgress(100);
        updateLoaderMessage('Export completed!');
        
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

/**
 * Export vault as downloadable encrypted file
 */
async function exportVaultAsFile(exportPassword) {
    showLoader('Preparing export file...', true);
    
    try {
        updateLoaderProgress(20);
        updateLoaderMessage('Decrypting vault data...');
        
        const storedData = JSON.parse(localStorage.getItem(STORAGE_KEY));
        const nonce = hexToBytes(storedData.nonce);
        const ciphertext = hexToBytes(storedData.encrypted);
        
        const decryptedString = await decryptChaCha20(ciphertext, masterKey, nonce);
        
        if (!decryptedString) {
            hideLoader();
            showNotification('Failed to decrypt vault for export', 'error');
            return false;
        }
        
        const decryptedData = JSON.parse(decryptedString);
        
        updateLoaderProgress(50);
        updateLoaderMessage('Generating export keys...');
        
        const exportSalt = generateRandomBytes(32);
        const exportNonce = generateRandomBytes(24);
        
        updateLoaderProgress(70);
        updateLoaderMessage('Encrypting export data...');
        
        const exportKey = await deriveKeyArgon2(exportPassword, exportSalt);
        const exportPlaintext = JSON.stringify(decryptedData);
        const encryptedExport = await encryptChaCha20(exportPlaintext, exportKey, exportNonce);
        
        updateLoaderProgress(90);
        updateLoaderMessage('Creating backup file...');
        
        const exportData = {
            encrypted: bytesToHex(encryptedExport),
            nonce: bytesToHex(exportNonce),
            salt: bytesToHex(exportSalt),
            version: VAULT_VERSION,
            algorithm: ENCRYPTION_ALGORITHM,
            exportedAt: new Date().toISOString()
        };
        
        const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
        const filename = `matrix-vault-backup-${timestamp}.mvault`;
        
        downloadFile(JSON.stringify(exportData, null, 2), filename, 'application/json');
        
        updateLoaderProgress(100);
        updateLoaderMessage('File downloaded successfully!');
        
        await new Promise(resolve => setTimeout(resolve, 300));
        
        hideLoader();
        showNotification('Vault backup downloaded successfully', 'success');
        return true;
    } catch (error) {
        console.error("Export file error:", error);
        showNotification('Export file failed', 'error');
        hideLoader();
        return false;
    }
}

/**
 * Import vault from encrypted backup
 */
async function importVault(exportedText, importPassword) {
    showLoader('Processing import...', true);
    
    try {
        updateLoaderProgress(20);
        updateLoaderMessage('Validating import data...');
        
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
        
        const salt = hexToBytes(importData.salt);
        const importKey = await deriveKeyArgon2(importPassword, salt);
        
        updateLoaderProgress(70);
        updateLoaderMessage('Decrypting import data...');
        
        const nonce = hexToBytes(importData.nonce);
        const ciphertext = hexToBytes(importData.encrypted);
        
        const decryptedString = await decryptChaCha20(ciphertext, importKey, nonce);
        
        if (!decryptedString) {
            hideLoader();
            showNotification('Invalid import password or corrupted data', 'error');
            return false;
        }
        
        const decryptedData = JSON.parse(decryptedString);
        
        updateLoaderProgress(90);
        updateLoaderMessage('Merging with existing vault...');
        
        // Create a map of existing passwords by ID for quick lookup
        const existingPasswordsMap = new Map();
        vault.passwords.forEach(pwd => existingPasswordsMap.set(pwd.id, pwd));
        
        // Add imported passwords, updating existing ones if newer
        if (decryptedData.passwords && Array.isArray(decryptedData.passwords)) {
            decryptedData.passwords.forEach(importedPwd => {
                if (existingPasswordsMap.has(importedPwd.id)) {
                    const existingPwd = existingPasswordsMap.get(importedPwd.id);
                    
                    // If imported password is newer, replace the existing one
                    const existingUpdated = new Date(existingPwd.updatedAt || 0);
                    const importedUpdated = new Date(importedPwd.updatedAt || 0);
                    
                    if (importedUpdated > existingUpdated) {
                        existingPasswordsMap.set(importedPwd.id, importedPwd);
                    }
                } else {
                    existingPasswordsMap.set(importedPwd.id, importedPwd);
                }
            });
        }
        
        vault.passwords = Array.from(existingPasswordsMap.values());
        
        await saveVault();
        renderPasswordList(vault.passwords);
        
        updateLoaderProgress(100);
        updateLoaderMessage('Import completed!');
        
        await new Promise(resolve => setTimeout(resolve, 300));
        
        hideLoader();
        showNotification(`Vault imported successfully. Total entries: ${vault.passwords.length}`, 'success');
        return true;
    } catch (error) {
        console.error("Import error:", error);
        hideLoader();
        showNotification('Error during import process', 'error');
        return false;
    }
}

/**
 * Reset vault state
 */
function resetVault() {
    masterKey = null;
    vault = {
        passwords: [],
        salt: null,
        nonce: null,
        version: VAULT_VERSION,
        lastAccess: null
    };
    
    clearAutoLogout();
}

// ============================================================================
// PASSWORD MANAGEMENT
// ============================================================================

/**
 * Show password details modal
 */
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
        const validatedURL = validateAndSanitizeURL(password.url);
        if (validatedURL) {
            elements.urlContainer.style.display = 'flex';
            elements.detailUrl.textContent = sanitizeText(password.url);
            elements.detailUrlLink.href = validatedURL;
            elements.detailUrlLink.setAttribute('rel', 'noopener noreferrer');
        } else {
            elements.urlContainer.style.display = 'none';
        }
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

/**
 * Add new password entry
 */
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
    
    // Validate URL if provided
    if (url && !validateAndSanitizeURL(url)) {
        showNotification('Invalid URL format', 'error');
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

/**
 * Update existing password entry
 */
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
    
    // Validate URL if provided
    if (url && !validateAndSanitizeURL(url)) {
        showNotification('Invalid URL format', 'error');
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

/**
 * Delete password entry with confirmation
 */
function deletePassword(id) {
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

/**
 * Generate and set password
 */
function generateAndSetPassword() {
    const length = 20;
    const includeSymbols = true;
    const password = generatePassword(length, includeSymbols);
    elements.newPassword.value = password;
    elements.newPassword.type = 'text';
    elements.newTogglePassword.textContent = 'HIDE';
    
    const strength = checkPasswordStrength(password);
    elements.newPasswordStrength.textContent = `Strength: ${strength.label}`;
    elements.newPasswordStrength.className = `password-strength strength-${strength.class}`;
    
    elements.passwordMeterBar.style.width = `${(strength.score / 6) * 100}%`;
    if (strength.class === 'weak') {
        elements.passwordMeterBar.style.backgroundColor = '#ff3333';
    } else if (strength.class === 'medium') {
        elements.passwordMeterBar.style.backgroundColor = '#ffcc00';
    } else {
        elements.passwordMeterBar.style.backgroundColor = '#33ff33';
    }
    
    elements.passwordMeterBar.style.transition = 'width 0.5s ease-in-out, background-color 0.5s ease';
}

/**
 * Check password strength
 */
function checkPasswordStrength(password) {
    if (!password) return { score: 0, label: 'None', class: 'weak' };
    
    let score = 0;
    
    if (password.length >= 16) score += 3;
    else if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    if (/(.)\1\1/.test(password)) score -= 1;
    if (/^(?:password|admin|123456|qwerty|welcome)/i.test(password)) score -= 2;
    if (/(?:abcdef|qwerty|12345)/i.test(password)) score -= 1;
    
    if (score < 0) score = 0;
    if (score > 6) score = 6;
    
    if (score >= 5) return { score, label: 'Strong', class: 'strong' };
    if (score >= 3) return { score, label: 'Medium', class: 'medium' };
    return { score, label: 'Weak', class: 'weak' };
}

// ============================================================================
// UI HELPER FUNCTIONS
// ============================================================================

/**
 * Show modal
 */
function showModal(modalElement) {
    if (!modalElement) return;
    
    modalElement.setAttribute('role', 'dialog');
    modalElement.setAttribute('aria-modal', 'true');
    
    modalElement.querySelectorAll('.input-error').forEach(el => el.remove());
    
    const closeBtn = modalElement.querySelector('.close-btn');
    if (closeBtn) {
        setTimeout(() => closeBtn.focus(), 100);
    }
    
    modalElement.style.display = 'block';
    document.addEventListener('keydown', handleEscKeyForModal);
}

/**
 * Hide modal
 */
function hideModal(modalElement) {
    if (!modalElement) return;
    modalElement.style.display = 'none';
    document.removeEventListener('keydown', handleEscKeyForModal);
}

/**
 * Handle ESC key for modal closing
 */
function handleEscKeyForModal(e) {
    if (e.key === 'Escape') {
        const visibleModal = document.querySelector('.modal[style*="display: block"]');
        if (visibleModal) {
            hideModal(visibleModal);
        }
    }
}

/**
 * Show notification
 */
function showNotification(message, type = 'success', duration = 3000) {
    elements.notificationMessage.textContent = message;
    
    const iconElement = elements.notification.querySelector('.notification-icon');
    
    if (type === 'success') {
        iconElement.style.backgroundColor = '#33ff33';
    } else if (type === 'error') {
        iconElement.style.backgroundColor = '#ff3333';
    } else if (type === 'warning') {
        iconElement.style.backgroundColor = '#ffcc00';
    }
    
    elements.notification.classList.add('show');
    
    if (window.notificationTimeout) {
        clearTimeout(window.notificationTimeout);
    }
    
    window.notificationTimeout = setTimeout(() => {
        elements.notification.classList.remove('show');
    }, duration);
}

/**
 * Clear form
 */
function clearForm(formModal) {
    const inputs = formModal.querySelectorAll('input, textarea');
    inputs.forEach(input => {
        if (input.type !== 'hidden') {
            input.value = '';
        }
    });
    
    const strengthIndicators = formModal.querySelectorAll('.password-strength');
    strengthIndicators.forEach(indicator => {
        indicator.textContent = '';
        indicator.className = 'password-strength';
    });
    
    const meterBars = formModal.querySelectorAll('.password-meter-bar');
    meterBars.forEach(bar => {
        bar.style.width = '0';
        bar.style.backgroundColor = '#333';
    });
}

/**
 * Show screen
 */
function showScreen(screenElement) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    screenElement.classList.add('active');
    
    if (screenElement === elements.vaultScreen) {
        updateEntryCount();
    }
}

/**
 * Update entry count
 */
function updateEntryCount() {
    if (elements.entryCount) {
        elements.entryCount.textContent = `${vault.passwords.length} entries`;
    }
}

/**
 * Toggle password visibility
 */
function togglePasswordVisibility(inputElement, buttonElement) {
    if (inputElement.type === 'password') {
        inputElement.type = 'text';
        buttonElement.textContent = 'HIDE';
    } else {
        inputElement.type = 'password';
        buttonElement.textContent = 'SHOW';
    }
}

/**
 * Show loader
 */
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
    
    setTimeout(() => {
        loaderElement.style.opacity = '1';
    }, 10);
}

/**
 * Update loader progress
 */
function updateLoaderProgress(percent) {
    const progressBar = document.getElementById('loader-progress-bar');
    if (progressBar) {
        progressBar.style.width = `${percent}%`;
    }
}

/**
 * Update loader message
 */
function updateLoaderMessage(message) {
    const messageElement = document.getElementById('loader-message');
    if (messageElement) {
        messageElement.textContent = message;
    }
}

/**
 * Hide loader
 */
function hideLoader() {
    const loaderElement = document.getElementById('loader');
    if (loaderElement) {
        loaderElement.style.opacity = '0';
        setTimeout(() => {
            loaderElement.remove();
        }, 300);
    }
}

/**
 * Render password list
 */
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
            
            updateEntryCount();
            hideLoader();
            return;
        }
        
        filteredPasswords.forEach((password, index) => {
            const item = document.createElement('div');
            item.className = 'password-item';
            item.dataset.id = password.id;
            
            if (animationLevel === 'full') {
                item.style.animationDelay = `${index * 0.05}s`;
            }
            
            const title = document.createElement('h4');
            title.textContent = sanitizeText(password.title || 'Unnamed Entry');
            
            const username = document.createElement('p');
            username.textContent = sanitizeText(password.username || 'No username');
            
            const health = document.createElement('div');
            health.className = 'password-health';
            const passwordStrength = checkPasswordStrength(password.password);
            
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
        
        updateEntryCount();
        hideLoader();
    }, 50);
}

// ============================================================================
// BACKGROUND EFFECTS
// ============================================================================

/**
 * Initialize Matrix background effect
 */
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
        const randomBytes = generateRandomBytes(1);
        return chars.charAt(randomBytes[0] % chars.length);
    }
    
    let lastDraw = 0;
    const fps = 8;
    const interval = 1000 / fps;
    
    function draw(timestamp) {
        if (timestamp - lastDraw < interval) {
            requestAnimationFrame(draw);
            return;
        }
        
        lastDraw = timestamp;
        
        ctx.fillStyle = 'rgba(0, 0, 0, 0.03)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#0f0';
        ctx.font = `${fontSize}px monospace`;
        
        for (let i = 0; i < drops.length; i++) {
            const text = getRandomChar();
            const x = i * fontSize;
            const y = drops[i] * fontSize;
            
            const green = 100 + Math.floor(Math.random() * 156);
            ctx.fillStyle = `rgba(0, ${green}, 0, ${0.7 + Math.random() * 0.3})`;
            
            ctx.fillText(text, x, y);
            
            if (y > canvas.height && Math.random() > 0.995) {
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

/**
 * Initialize particles background effect
 */
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

// ============================================================================
// AUTO-LOGOUT
// ============================================================================

/**
 * Setup auto-logout on inactivity
 */
function setupAutoLogout(minutes) {
    let inactivityTime = 0;
    const intervalTime = 1;
    const maxInactivity = minutes * 60;
    
    const resetTimer = () => {
        inactivityTime = 0;
        if (elements.logoutTimer.style.display === 'block') {
            elements.logoutTimer.style.display = 'none';
        }
    };
    
    ['click', 'touchstart', 'mousemove', 'keypress', 'scroll'].forEach(event => {
        document.addEventListener(event, resetTimer);
    });
    
    clearAutoLogout();
    
    window.autoLogoutInterval = setInterval(() => {
        if (elements.vaultScreen.classList.contains('active')) {
            inactivityTime += intervalTime;
            
            const timeLeft = maxInactivity - inactivityTime;
            if (timeLeft <= 60 && elements.logoutTimer) {
                const minutes = Math.floor(timeLeft / 60);
                const seconds = timeLeft % 60;
                elements.logoutTimer.textContent = `Auto-logout in: ${minutes}:${seconds.toString().padStart(2, '0')}`;
                elements.logoutTimer.style.display = 'block';
            }
            
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

/**
 * Clear auto-logout
 */
function clearAutoLogout() {
    if (window.autoLogoutInterval) {
        clearInterval(window.autoLogoutInterval);
    }
    if (elements.logoutTimer) {
        elements.logoutTimer.style.display = 'none';
    }
}

/**
 * Apply animation level
 */
function applyAnimationLevel(level) {
    document.body.classList.remove('minimal-animations', 'no-animations');
    
    switch (level) {
        case 'minimal':
            document.body.classList.add('minimal-animations');
            break;
        case 'none':
            document.body.classList.add('no-animations');
            break;
    }
    
    localStorage.setItem(ANIMATION_STORAGE_KEY, level);
    animationLevel = level;
}

/**
 * Change master password
 */
async function changeMasterPassword(currentPassword, newPassword) {
    try {
        showLoader('Verifying current password...', true);
        
        if (await unlockVault(currentPassword)) {
            updateLoaderProgress(30);
            updateLoaderMessage('Decrypting vault data...');
            
            const storedData = JSON.parse(localStorage.getItem(STORAGE_KEY));
            const nonce = hexToBytes(storedData.nonce);
            const ciphertext = hexToBytes(storedData.encrypted);
            
            const decryptedString = await decryptChaCha20(ciphertext, masterKey, nonce);
            
            if (!decryptedString) {
                hideLoader();
                showNotification('Failed to decrypt vault', 'error');
                return false;
            }
            
            updateLoaderProgress(50);
            updateLoaderMessage('Generating new security keys...');
            
            const newSalt = generateRandomBytes(32);
            vault.salt = bytesToHex(newSalt);
            
            updateLoaderProgress(70);
            updateLoaderMessage('Deriving new encryption key...');
            
            masterKey = await deriveKeyArgon2(newPassword, newSalt);
            
            updateLoaderProgress(90);
            updateLoaderMessage('Saving vault with new password...');
            
            await saveVault();
            
            updateLoaderProgress(100);
            updateLoaderMessage('Password changed successfully!');
            
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

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // Login button
    elements.loginBtn.addEventListener('click', async () => {
        if (!checkRateLimit()) {
            updateRateLimitDisplay();
            return;
        }
        
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
                recordFailedAttempt();
                showNotification('Incorrect password', 'error');
                elements.masterPassword.value = '';
                elements.masterPassword.focus();
                
                if (!checkRateLimit()) {
                    updateRateLimitDisplay();
                }
            }
        } else {
            showNotification('No vault found. Create a new one.', 'warning');
        }
    });
    
    // Create vault button
    elements.createVaultBtn.addEventListener('click', async () => {
        const password = elements.masterPassword.value;
        if (!password) {
            showNotification('Please enter a password', 'warning');
            elements.masterPassword.focus();
            return;
        }
        
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
    
    // Master password enter key
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
    
    // Vault screen buttons
    elements.addBtn.addEventListener('click', () => {
        clearForm(elements.addPasswordModal);
        showModal(elements.addPasswordModal);
        setTimeout(() => elements.newTitle.focus(), 100);
    });
    
    elements.exportBtn.addEventListener('click', () => {
        clearForm(elements.exportModal);
        document.querySelector('.export-text-area').style.display = 'none';
        elements.confirmExportBtn.style.display = 'block';
        
        // Add export as file button
        const buttonContainer = document.querySelector('#export-modal .modal-buttons');
        const existingFileBtn = buttonContainer.querySelector('#export-file-btn');
        if (existingFileBtn) existingFileBtn.remove();
        
        const exportFileBtn = document.createElement('button');
        exportFileBtn.id = 'export-file-btn';
        exportFileBtn.className = 'secondary-btn';
        exportFileBtn.textContent = 'DOWNLOAD FILE';
        
        buttonContainer.parentElement.insertBefore(exportFileBtn, buttonContainer.nextSibling);
        
        exportFileBtn.addEventListener('click', async () => {
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
            
            await exportVaultAsFile(exportPassword);
        });
        
        showModal(elements.exportModal);
        setTimeout(() => elements.exportPassword.focus(), 100);
    });
    
    elements.importBtn.addEventListener('click', () => {
        clearForm(elements.importModal);
        
        // Add file input for importing files
        const importContainer = elements.importModal.querySelector('.input-container');
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.id = 'import-file-input';
        fileInput.accept = '.mvault,application/json';
        fileInput.style.marginBottom = '10px';
        
        const existingFileInput = elements.importModal.querySelector('#import-file-input');
        if (existingFileInput) existingFileInput.remove();
        
        importContainer.parentElement.insertBefore(fileInput, importContainer);
        
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    elements.importText.value = event.target.result;
                };
                reader.readAsText(file);
            }
        });
        
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
    
    // Toggle password visibility in detail modal
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
                    showNotification(successful ? `${field.charAt(0).toUpperCase() + field.slice(1)} copied` : 'Failed to copy', successful ? 'success' : 'error');
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
            document.querySelector('.export-text-area').style.display = 'block';
            document.getElementById('export-text').value = exportedData;
            elements.confirmExportBtn.style.display = 'none';
            showNotification('Vault data ready for export', 'success');
            
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
        document.querySelector('.export-text-area').style.display = 'none';
        elements.exportText.value = '';
        elements.confirmExportBtn.style.display = 'block';
        
        const fileBtn = document.getElementById('export-file-btn');
        if (fileBtn) fileBtn.remove();
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
        
        const fileInput = elements.importModal.querySelector('#import-file-input');
        if (fileInput) fileInput.remove();
    });
    
    // Settings button
    if (elements.settingsBtn) {
        elements.settingsBtn.addEventListener('click', () => {
            showModal(elements.settingsModal);
            
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
            message.innerHTML = '<strong>WARNING:</strong> This will permanently delete all your saved passwords and vault data. This action cannot be undone.<br><br>Type "DELETE" below to confirm.';
            
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

// ============================================================================
// INITIALIZATION
// ============================================================================

function init() {
    animationLevel = localStorage.getItem(ANIMATION_STORAGE_KEY) || 'full';
    applyAnimationLevel(animationLevel);
    
    initMatrixBackground();
    if (animationLevel === 'full') {
        initParticlesBackground();
    }
    
    setupEventListeners();
    
    // Set Content Security Policy
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'";
    document.head.appendChild(meta);
    
    if (loadVault()) {
        showScreen(elements.loginScreen);
    } else {
        showScreen(elements.loginScreen);
        elements.createVaultBtn.style.display = 'block';
    }
}

// Start the app when DOM is loaded
document.addEventListener('DOMContentLoaded', init);
