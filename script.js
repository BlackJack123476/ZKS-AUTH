/**
 * Main application logic for ZKS Auth
 */

class ZKSAuth {
    constructor() {
        console.log('ZKSAuth initializing...');
        console.log('TOTP available:', typeof TOTP);
        this.totp = new TOTP();
        this.currentSecret = '';
        this.timerInterval = null;
        this.codeGenerationInterval = null;
        this.init();
        console.log('ZKSAuth initialized successfully');
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        // Generate button
        const generateBtn = document.getElementById('generate-btn');
        const secretInput = document.getElementById('secret-key');
        
        generateBtn.addEventListener('click', () => {
            const secret = secretInput.value.trim();
            this.generateCode(secret);
        });

        // Enter key support
        secretInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const secret = secretInput.value.trim();
                this.generateCode(secret);
            }
        });

        // Real-time validation
        secretInput.addEventListener('input', (e) => {
            this.validateSecretInput(e.target.value);
        });
    }

    validateSecretInput(secret) {
        const generateBtn = document.getElementById('generate-btn');
        const secretInput = document.getElementById('secret-key');
        
        const isValid = this.totp.validateSecret(secret);
        
        if (secret.length === 0) {
            // Reset styling for empty input
            secretInput.style.borderColor = 'rgba(187, 134, 252, 0.3)';
            generateBtn.disabled = false;
            generateBtn.style.opacity = '1';
        } else if (isValid) {
            // Valid secret
            secretInput.style.borderColor = '#4caf50';
            generateBtn.disabled = false;
            generateBtn.style.opacity = '1';
        } else {
            // Invalid secret
            secretInput.style.borderColor = '#f44336';
            generateBtn.disabled = true;
            generateBtn.style.opacity = '0.6';
        }
    }

    async generateCode(secret) {
        if (!secret) {
            this.showError('Please enter a secret key');
            return;
        }

        if (!this.totp.validateSecret(secret)) {
            this.showError('Invalid secret key format. Please enter a valid base32 encoded key.');
            return;
        }

        try {
            this.currentSecret = secret;
            
            // Generate initial code
            const code = await this.generateTOTPCode(secret);
            
            // Show the code
            this.displayCode(code);
            
            // Start the timer and auto-refresh
            this.startTimer();
            this.startAutoRefresh();

        } catch (error) {
            console.error('Code generation error:', error);
            this.showError('Error generating code. Please check your secret key.');
        }
    }

    async generateTOTPCode(secret) {
        // Generate code - now always async
        return await this.totp.generate(secret);
    }

    displayCode(code) {
        const codeDisplay = document.getElementById('code-display');
        const codeValue = document.getElementById('code-value');
        
        codeValue.textContent = code;
        codeDisplay.classList.remove('hidden');
        
        // Add a subtle animation
        codeValue.style.animation = 'none';
        setTimeout(() => {
            codeValue.style.animation = 'pulse 0.5s ease-in-out';
        }, 10);
    }

    startTimer() {
        this.updateTimer();
        this.timerInterval = setInterval(() => {
            this.updateTimer();
        }, 1000);
    }

    updateTimer() {
        const remaining = this.totp.getRemainingSeconds();
        const timerSeconds = document.getElementById('timer-seconds');
        const timerProgress = document.getElementById('timer-progress');
        
        if (timerSeconds) {
            timerSeconds.textContent = remaining;
        }
        
        if (timerProgress) {
            const percentage = (remaining / 30) * 100;
            timerProgress.style.width = `${percentage}%`;
            
            // Change color as time runs out
            if (remaining <= 5) {
                timerProgress.style.background = 'linear-gradient(90deg, #f44336, #ff5722)';
            } else if (remaining <= 10) {
                timerProgress.style.background = 'linear-gradient(90deg, #ff9800, #f44336)';
            } else {
                timerProgress.style.background = 'linear-gradient(90deg, #4fc3f7, #29b6f6)';
            }
        }
    }

    startAutoRefresh() {
        // Check for code refresh every second
        this.codeGenerationInterval = setInterval(async () => {
            const remaining = this.totp.getRemainingSeconds();
            
            // Refresh code when timer reaches 0 (or very close)
            if (remaining <= 1 && this.currentSecret) {
                const newCode = await this.generateTOTPCode(this.currentSecret);
                this.displayCode(newCode);
            }
        }, 1000);
    }

    stopTimers() {
        if (this.timerInterval) {
            clearInterval(this.timerInterval);
            this.timerInterval = null;
        }
        
        if (this.codeGenerationInterval) {
            clearInterval(this.codeGenerationInterval);
            this.codeGenerationInterval = null;
        }
    }

    showError(message) {
        // Create error notification
        const notification = document.createElement('div');
        notification.className = 'error-notification';
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #f44336;
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(244, 67, 54, 0.3);
            z-index: 9999;
            animation: slideIn 0.3s ease-out;
        `;

        document.body.appendChild(notification);

        // Auto-remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
}

// CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
`;
document.head.appendChild(style);

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Check if TOTP class is available
    if (typeof TOTP === 'undefined') {
        console.error('TOTP class not found. Make sure totp.js is loaded first.');
        return;
    }
    
    window.zksAuth = new ZKSAuth();
});

// Clean up timers when page is unloaded
window.addEventListener('beforeunload', () => {
    if (window.zksAuth) {
        window.zksAuth.stopTimers();
    }
});