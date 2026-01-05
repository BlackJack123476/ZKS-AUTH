/**
 * TOTP (Time-based One-Time Password) Implementation
 * Compatible with RFC 6238 standard used by Rockstar Games and other services
 */

class TOTP {
    constructor() {
        this.timeStep = 30; // 30 second intervals
        this.codeDigits = 6; // 6 digit codes
    }

    /**
     * Generate TOTP code from secret key
     * @param {string} secret - Base32 encoded secret key
     * @param {number} time - Unix timestamp (optional, defaults to current time)
     * @returns {Promise<string>} 6-digit TOTP code
     */
    async generate(secret, time = null) {
        try {
            // Use current time if not provided
            if (time === null) {
                time = Math.floor(Date.now() / 1000);
            }

            // Calculate time counter
            const counter = Math.floor(time / this.timeStep);

            // Clean and decode base32 secret - remove spaces, dashes, and fix common character issues
            let cleanSecret = secret.replace(/[\s\-]/g, '').toUpperCase();
            
            // Fix common character substitutions in Rockstar Games keys
            // 0 (zero) -> O (letter O), 1 (one) -> I (letter I)
            cleanSecret = cleanSecret.replace(/0/g, 'O').replace(/1/g, 'I');
            
            console.log('TOTP Debug:', {
                original: secret,
                cleaned: cleanSecret,
                timeCounter: counter,
                time: time
            });
            
            const key = this.base32Decode(cleanSecret);
            
            // Generate HMAC-SHA1
            const hmac = await this.hmacSha1(key, this.intToBytes(counter));
            
            // Dynamic truncation
            const code = this.dynamicTruncate(hmac);
            
            const result = String(code).padStart(this.codeDigits, '0');
            console.log('TOTP Generated:', result);
            
            // Return 6-digit code with leading zeros
            return result;
        } catch (error) {
            console.error('TOTP generation error:', error);
            console.error('Secret:', secret);
            // Return error code instead of 000000 to help debug
            return 'ERROR';
        }
    }

    /**
     * Get remaining seconds until next code generation
     * @returns {number} Seconds remaining
     */
    getRemainingSeconds() {
        const now = Math.floor(Date.now() / 1000);
        return this.timeStep - (now % this.timeStep);
    }

    /**
     * Validate if secret key format is correct
     * @param {string} secret - Secret key to validate
     * @returns {boolean} True if valid
     */
    validateSecret(secret) {
        try {
            let cleaned = secret.replace(/[\s\-]/g, '').toUpperCase();
            // Apply same character fixes as in generate()
            cleaned = cleaned.replace(/0/g, 'O').replace(/1/g, 'I');
            // Check if it's valid base32 (A-Z, 2-7, =) and reasonable length
            return /^[A-Z2-7=]+$/.test(cleaned) && cleaned.length >= 16;
        } catch {
            return false;
        }
    }

    /**
     * Base32 decode implementation
     * @private
     */
    base32Decode(encoded) {
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        
        // Remove padding and convert to uppercase
        encoded = encoded.replace(/=/g, '').toUpperCase();
        
        let bits = '';
        // Convert each character to 5-bit binary
        for (let i = 0; i < encoded.length; i++) {
            const char = encoded[i];
            const index = base32Chars.indexOf(char);
            if (index === -1) {
                throw new Error(`Invalid base32 character: ${char}`);
            }
            bits += index.toString(2).padStart(5, '0');
        }

        // Convert bits to bytes (8-bit chunks)
        const bytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            const byte = parseInt(bits.substr(i, 8), 2);
            bytes.push(byte);
        }

        return new Uint8Array(bytes);
    }

    /**
     * Convert integer to 8-byte array (big-endian)
     * @private
     */
    intToBytes(int) {
        const bytes = new Uint8Array(8);
        for (let i = 7; i >= 0; i--) {
            bytes[i] = int & 0xff;
            int = Math.floor(int / 256);
        }
        return bytes;
    }

    /**
     * HMAC-SHA1 implementation
     * @private
     */
    async hmacSha1(key, message) {
        // Try Web Crypto API first
        if (typeof crypto !== 'undefined' && crypto.subtle) {
            try {
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    key,
                    { name: 'HMAC', hash: 'SHA-1' },
                    false,
                    ['sign']
                );
                const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
                return new Uint8Array(signature);
            } catch (error) {
                console.warn('Web Crypto API failed, using fallback');
            }
        }

        // Fallback implementation - simplified and more reliable
        return this.hmacSha1Simple(key, message);
    }

    /**
     * Simplified HMAC-SHA1 fallback
     * @private
     */
    hmacSha1Simple(key, message) {
        const blockSize = 64;
        
        // Pad or hash key if needed
        if (key.length > blockSize) {
            key = this.sha1Simple(key);
        }
        
        // Pad key to block size
        const paddedKey = new Uint8Array(blockSize);
        paddedKey.set(key);
        
        // Create inner and outer pads
        const innerPad = new Uint8Array(blockSize);
        const outerPad = new Uint8Array(blockSize);
        
        for (let i = 0; i < blockSize; i++) {
            innerPad[i] = paddedKey[i] ^ 0x36;
            outerPad[i] = paddedKey[i] ^ 0x5c;
        }
        
        // HMAC = SHA1(outerPad + SHA1(innerPad + message))
        const innerData = new Uint8Array(innerPad.length + message.length);
        innerData.set(innerPad);
        innerData.set(message, innerPad.length);
        
        const innerHash = this.sha1Simple(innerData);
        
        const outerData = new Uint8Array(outerPad.length + innerHash.length);
        outerData.set(outerPad);
        outerData.set(innerHash, outerPad.length);
        
        return this.sha1Simple(outerData);
    }

    /**
     * Simplified SHA-1 implementation
     * @private
     */
    sha1Simple(data) {
        // Initialize hash values
        let h0 = 0x67452301;
        let h1 = 0xEFCDAB89;
        let h2 = 0x98BADCFE;
        let h3 = 0x10325476;
        let h4 = 0xC3D2E1F0;

        // Pre-processing
        const msgLength = data.length * 8;
        const paddedData = new Uint8Array(data.length + 1 + (64 - (data.length + 1 + 8) % 64) % 64 + 8);
        paddedData.set(data);
        paddedData[data.length] = 0x80;
        
        // Add length as 64-bit big-endian
        for (let i = 0; i < 8; i++) {
            paddedData[paddedData.length - 8 + i] = (msgLength >>> (56 - i * 8)) & 0xFF;
        }

        // Process message in 512-bit chunks
        for (let chunk = 0; chunk < paddedData.length; chunk += 64) {
            const w = new Array(80);
            
            // Break chunk into sixteen 32-bit words
            for (let i = 0; i < 16; i++) {
                w[i] = (paddedData[chunk + i * 4] << 24) |
                       (paddedData[chunk + i * 4 + 1] << 16) |
                       (paddedData[chunk + i * 4 + 2] << 8) |
                       (paddedData[chunk + i * 4 + 3]);
            }

            // Extend sixteen 32-bit words into eighty 32-bit words
            for (let i = 16; i < 80; i++) {
                w[i] = this.rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            // Initialize hash value for this chunk
            let a = h0, b = h1, c = h2, d = h3, e = h4;

            // Main loop
            for (let i = 0; i < 80; i++) {
                let f, k;
                if (i < 20) {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                const temp = (this.rotateLeft(a, 5) + f + e + k + w[i]) >>> 0;
                e = d;
                d = c;
                c = this.rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            // Add this chunk's hash to result
            h0 = (h0 + a) >>> 0;
            h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0;
            h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0;
        }

        // Convert hash to byte array
        const result = new Uint8Array(20);
        const hashes = [h0, h1, h2, h3, h4];
        for (let i = 0; i < 5; i++) {
            for (let j = 0; j < 4; j++) {
                result[i * 4 + j] = (hashes[i] >>> (24 - j * 8)) & 0xFF;
            }
        }

        return result;
    }

    /**
     * Rotate left helper function
     * @private
     */
    rotateLeft(n, rotateCount) {
        return ((n << rotateCount) | (n >>> (32 - rotateCount))) >>> 0;
    }

    /**
     * Concatenate two Uint8Arrays
     * @private
     */
    concatArrays(a, b) {
        const result = new Uint8Array(a.length + b.length);
        result.set(a);
        result.set(b, a.length);
        return result;
    }

    /**
     * Dynamic truncate function for HOTP/TOTP
     * @private
     */
    dynamicTruncate(hmac) {
        const offset = hmac[hmac.length - 1] & 0x0F;
        const code = ((hmac[offset] & 0x7F) << 24) |
                     ((hmac[offset + 1] & 0xFF) << 16) |
                     ((hmac[offset + 2] & 0xFF) << 8) |
                     (hmac[offset + 3] & 0xFF);
        
        return code % Math.pow(10, this.codeDigits);
    }
}

// Export for use in other files
window.TOTP = TOTP;

// Debug: Log that TOTP class is loaded
console.log('TOTP class loaded successfully');