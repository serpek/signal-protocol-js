
import { CryptoUtils } from './utils';
import { KeyPair } from '../types/signal.types';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'DoubleRatchet' });

export interface RatchetHeader {
    publicKey: Uint8Array;
    previousCounter: number;
    counter: number;
}

export interface DoubleRatchetState {
    DHs?: KeyPair;                    // Sending DH ratchet key pair
    DHr?: Uint8Array;                  // Receiving DH ratchet public key
    RK: Uint8Array;                    // Root key
    CKs?: Uint8Array;                  // Sending chain key
    CKr?: Uint8Array;                  // Receiving chain key
    Ns: number;                        // Sending message number
    Nr: number;                        // Receiving message number
    PN: number;                        // Previous chain length
    MKSKIPPED: Map<string, Uint8Array>; // Skipped message keys
}

export class DoubleRatchet {
    private state: DoubleRatchetState;
    private readonly MAX_SKIP = 1000;

    constructor() {
        this.state = {
            RK: new Uint8Array(32),
            Ns: 0,
            Nr: 0,
            PN: 0,
            MKSKIPPED: new Map()
        };
    }

    async initializeAsSender(
        sharedSecret: Uint8Array,
        remotePublicKey: Uint8Array
    ): Promise<void> {
        logger.info('Initializing Double Ratchet as sender');

        this.state.DHs = await CryptoUtils.generateX25519KeyPair();
        this.state.DHr = remotePublicKey;

        // Derive initial root key and sending chain key
        const dhOutput = await CryptoUtils.performDH(this.state.DHs.privateKey, remotePublicKey);
        const derivedKeys = await this.kdfRK(sharedSecret, dhOutput);

        this.state.RK = derivedKeys.rootKey;
        this.state.CKs = derivedKeys.chainKey;
    }

    async initializeAsReceiver(
        sharedSecret: Uint8Array,
        keyPair: KeyPair
    ): Promise<void> {
        logger.info('Initializing Double Ratchet as receiver');

        this.state.DHs = keyPair;
        this.state.RK = sharedSecret;
    }

    async encrypt(plaintext: Uint8Array, associatedData: Uint8Array): Promise<[RatchetHeader, Uint8Array]> {
        if (!this.state.CKs || !this.state.DHs) {
            throw new Error('Ratchet not properly initialized for sending');
        }

        // Derive message key from chain key
        const messageKey = await this.kdfCK(this.state.CKs);
        this.state.CKs = messageKey.chainKey;

        // Create header
        const header: RatchetHeader = {
            publicKey: this.state.DHs.publicKey,
            previousCounter: this.state.PN,
            counter: this.state.Ns
        };

        // Increment send counter
        this.state.Ns++;

        // Encrypt message
        const headerBytes = this.serializeHeader(header);
        const ad = CryptoUtils.concatArrays(associatedData, headerBytes);
        const ciphertext = await CryptoUtils.encrypt(messageKey.messageKey, plaintext, ad);

        logger.debug(`Encrypted message ${header.counter}`);

        return [header, ciphertext];
    }

    async decrypt(
        header: RatchetHeader,
        ciphertext: Uint8Array,
        associatedData: Uint8Array
    ): Promise<Uint8Array> {
        // Try skipped message keys first
        const skippedKey = await this.trySkippedMessageKeys(header, ciphertext, associatedData);
        if (skippedKey) {
            return skippedKey;
        }

        // Check if we need to perform DH ratchet
        if (!this.state.DHr || !this.equalArrays(header.publicKey, this.state.DHr)) {
            await this.skipMessageKeys(header.previousCounter);
            await this.dhRatchet(header);
        }

        // Skip message keys if needed
        await this.skipMessageKeys(header.counter);

        // Derive message key
        if (!this.state.CKr) {
            throw new Error('Receiving chain key not initialized');
        }

        const messageKey = await this.kdfCK(this.state.CKr);
        this.state.CKr = messageKey.chainKey;
        this.state.Nr++;

        // Decrypt message
        const headerBytes = this.serializeHeader(header);
        const ad = CryptoUtils.concatArrays(associatedData, headerBytes);
        const plaintext = await CryptoUtils.decrypt(messageKey.messageKey, ciphertext, ad);

        logger.debug(`Decrypted message ${header.counter}`);

        return plaintext;
    }

    private async dhRatchet(header: RatchetHeader): Promise<void> {
        logger.debug('Performing DH ratchet step');

        this.state.PN = this.state.Ns;
        this.state.Ns = 0;
        this.state.Nr = 0;
        this.state.DHr = header.publicKey;

        // Generate new DH key pair
        const newDHs = await CryptoUtils.generateX25519KeyPair();

        // Derive new receiving chain key
        const dhOutput = await CryptoUtils.performDH(this.state.DHs!.privateKey, this.state.DHr);
        const receivingKeys = await this.kdfRK(this.state.RK, dhOutput);
        this.state.RK = receivingKeys.rootKey;
        this.state.CKr = receivingKeys.chainKey;

        // Update sending keys
        this.state.DHs = newDHs;
        const sendingDH = await CryptoUtils.performDH(this.state.DHs.privateKey, this.state.DHr);
        const sendingKeys = await this.kdfRK(this.state.RK, sendingDH);
        this.state.RK = sendingKeys.rootKey;
        this.state.CKs = sendingKeys.chainKey;
    }

    private async skipMessageKeys(until: number): Promise<void> {
        if (this.state.Nr + this.MAX_SKIP < until) {
            throw new Error('Too many skipped messages');
        }

        if (!this.state.CKr) {
            return;
        }

        while (this.state.Nr < until) {
            const messageKey = await this.kdfCK(this.state.CKr);
            this.state.CKr = messageKey.chainKey;

            const key = `${this.state.DHr}-${this.state.Nr}`;
            this.state.MKSKIPPED.set(key, messageKey.messageKey);
            this.state.Nr++;
        }
    }

    private async trySkippedMessageKeys(
        header: RatchetHeader,
        ciphertext: Uint8Array,
        associatedData: Uint8Array
    ): Promise<Uint8Array | null> {
        const key = `${header.publicKey}-${header.counter}`;
        const messageKey = this.state.MKSKIPPED.get(key);

        if (messageKey) {
            this.state.MKSKIPPED.delete(key);

            try {
                const headerBytes = this.serializeHeader(header);
                const ad = CryptoUtils.concatArrays(associatedData, headerBytes);
                const plaintext = await CryptoUtils.decrypt(messageKey, ciphertext, ad);

                logger.debug(`Used skipped message key for message ${header.counter}`);
                return plaintext;
            } catch (error) {
                logger.error('Failed to decrypt with skipped key:', error);
                return null;
            }
        }

        return null;
    }

    private async kdfRK(rootKey: Uint8Array, dhOutput: Uint8Array): Promise<{
        rootKey: Uint8Array;
        chainKey: Uint8Array;
    }> {
        const info = new TextEncoder().encode('Signal_Ratchet');
        const output = await CryptoUtils.deriveSecrets(dhOutput, rootKey, info, 64);

        return {
            rootKey: output.slice(0, 32),
            chainKey: output.slice(32, 64)
        };
    }

    private async kdfCK(chainKey: Uint8Array): Promise<{
        chainKey: Uint8Array;
        messageKey: Uint8Array;
    }> {
        const messageKeyInput = new Uint8Array([1]);
        const chainKeyInput = new Uint8Array([2]);

        const messageKey = await CryptoUtils.calculateMAC(chainKey, messageKeyInput);
        const newChainKey = await CryptoUtils.calculateMAC(chainKey, chainKeyInput);

        return {
            chainKey: newChainKey,
            messageKey
        };
    }

    private serializeHeader(header: RatchetHeader): Uint8Array {
        const buffer = new Uint8Array(32 + 4 + 4); // publicKey + previousCounter + counter
        buffer.set(header.publicKey, 0);

        const view = new DataView(buffer.buffer);
        view.setUint32(32, header.previousCounter, true);
        view.setUint32(36, header.counter, true);

        return buffer;
    }

    private equalArrays(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    exportState(): DoubleRatchetState {
        return {
            ...this.state,
            MKSKIPPED: new Map(this.state.MKSKIPPED)
        };
    }

    importState(state: DoubleRatchetState): void {
        this.state = {
            ...state,
            MKSKIPPED: new Map(state.MKSKIPPED)
        };
    }
}