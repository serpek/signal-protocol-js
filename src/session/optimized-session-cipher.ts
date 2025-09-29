
import { SessionCipher } from './session-cipher';
import { SignalProtocolStore } from '../store/signal-store';
import { PerformanceMonitor } from '../utils/performance-monitor';
import { CiphertextMessage } from './session-cipher';

export class OptimizedSessionCipher extends SessionCipher {
    private encryptionCache: Map<string, Uint8Array> = new Map();
    private readonly cacheSize = 100;

    constructor(store: SignalProtocolStore, recipientAddress: string, deviceId: number = 1) {
        super(store, recipientAddress, deviceId);
    }

    async encrypt(plaintext: Uint8Array): Promise<CiphertextMessage> {
        PerformanceMonitor.startTimer('encrypt');

        try {
            const result = await super.encrypt(plaintext);

            // Cache for potential retransmission
            const cacheKey = this.getCacheKey(plaintext);
            this.encryptionCache.set(cacheKey, result.body);

            // Maintain cache size
            if (this.encryptionCache.size > this.cacheSize) {
                const firstKey = this.encryptionCache.keys().next().value;
                if (firstKey) {
                    this.encryptionCache.delete(firstKey);
                }
            }

            return result;
        } finally {
            PerformanceMonitor.endTimer('encrypt', {
                messageSize: plaintext.length,
                recipient: this.getRecipientAddress()
            });
        }
    }

    async decrypt(message: CiphertextMessage): Promise<Uint8Array> {
        PerformanceMonitor.startTimer('decrypt');

        try {
            return await super.decrypt(message);
        } finally {
            PerformanceMonitor.endTimer('decrypt', {
                messageType: message.type,
                sender: this.getRecipientAddress()
            });
        }
    }

    private getCacheKey(plaintext: Uint8Array): string {
        // Simple hash for cache key
        let hash = 0;
        for (let i = 0; i < plaintext.length; i++) {
            hash = ((hash << 5) - hash) + plaintext[i];
            hash = hash & hash;
        }
        return `${this.getRecipientAddress()}_${hash}`;
    }
}