
import "fake-indexeddb/auto";
import { SignalProtocolStore } from '../store/signal-store';
import { SessionCipher } from '../session/session-cipher';
import { PreKeyBundle } from '../types/signal.types';
// import { setupIndexedDB } from './setup-indexeddb';

export class OurLibraryAdapter {
    private store: SignalProtocolStore;
    private initialized: boolean = false;

    constructor() {
        this.store = new SignalProtocolStore();
    }

    async initialize(): Promise<void> {
        if (!this.initialized) {
            // Ensure IndexedDB is available
            // await setupIndexedDB();

            await this.store.initialize();
            this.initialized = true;
        }
    }

    /**
     * Generate a prekey bundle for others to establish sessions
     */
    async generatePreKeyBundle(): Promise<PreKeyBundle> {
        await this.initialize();
        return await this.store.generatePreKeyBundle();
    }

    /**
     * Process a prekey bundle to establish a session
     */
    async processPreKeyBundle(recipientAddress: string, bundle: PreKeyBundle): Promise<void> {
        await this.initialize();
        const cipher = new SessionCipher(this.store, recipientAddress);
        await cipher.processPreKeyBundle(bundle);
    }

    /**
     * Encrypt a message
     */
    async encrypt(recipientAddress: string, plaintext: string): Promise<{
        type: number;
        body: Uint8Array;
        registrationId?: number;
        preKeyId?: number;
        signedPreKeyId?: number;
        baseKey?: Uint8Array;
        identityKey?: Uint8Array;
    }> {
        await this.initialize();
        const cipher = new SessionCipher(this.store, recipientAddress);
        const encrypted = await cipher.encrypt(new TextEncoder().encode(plaintext));

        return {
            type: encrypted.type,
            body: encrypted.body,
            registrationId: encrypted.registrationId,
            preKeyId: encrypted.preKeyId,
            signedPreKeyId: encrypted.signedPreKeyId,
            baseKey: encrypted.baseKey,
            identityKey: encrypted.identityKey
        };
    }

    /**
     * Decrypt a message
     */
    async decrypt(senderAddress: string, ciphertext: {
        type: number;
        body: Uint8Array;
        registrationId?: number;
        preKeyId?: number;
        signedPreKeyId?: number;
        baseKey?: Uint8Array;
        identityKey?: Uint8Array;
    }): Promise<string> {
        await this.initialize();
        const cipher = new SessionCipher(this.store, senderAddress);
        const plaintext = await cipher.decrypt(ciphertext);
        return new TextDecoder().decode(plaintext);
    }

    /**
     * Get identity public key
     */
    async getIdentityPublicKey(): Promise<Uint8Array> {
        await this.initialize();
        const keyPair = await this.store.getIdentityKeyPair();
        return keyPair.publicKey;
    }
}