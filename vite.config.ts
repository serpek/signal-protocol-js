import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
    plugins: [react()],
    define: {
        global: 'globalThis',
    },
    optimizeDeps: {
        include: [
            '@noble/curves/ed25519',
            '@noble/ciphers/chacha',
            '@noble/hashes/sha256',
            '@noble/hashes/hkdf',
            '@noble/post-quantum',
            'dexie',
            'dexie-encrypted',
            'tslog'
        ],
    },
    build: {
        target: 'es2020',
        rollupOptions: {
            output: {
                manualChunks: {
                    crypto: ['@noble/curves', '@noble/ciphers', '@noble/hashes', '@noble/post-quantum'],
                    storage: ['dexie', 'dexie-encrypted'],
                },
            },
        },
    },
});