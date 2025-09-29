
import { SignalDatabase } from '../storage/signal-database';
import { CryptoUtils } from '../crypto/utils';
import {
    KeyPair,
    PreKey,
    SignedPreKey,
    PreKeyBundle,
    SessionState
} from '../types/signal.types';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'SignalStore' });

export class SignalProtocolStore {
    private db: SignalDatabase;
    private identityKeyPair?: KeyPair;
    private registrationId?: number;

    constructor() {
        this.db = new SignalDatabase();
    }

    async initialize(encryptionKey?: Uint8Array): Promise<void> {
        logger.info('Initializing Signal Protocol Store');

        await this.db.initialize(encryptionKey);

        // Load or generate identity key pair
        this.identityKeyPair = await this.db.getIdentityKeyPair();
        if (!this.identityKeyPair) {
            this.identityKeyPair = await CryptoUtils.generateKeyPair();
            await this.db.setIdentityKeyPair(this.identityKeyPair as KeyPair);
            logger.info('Generated new identity key pair');
        }

        // Load or generate registration ID
        this.registrationId = await this.db.getLocalRegistrationId();

        logger.info('Signal Protocol Store initialized');
    }

    // Identity operations
    async getIdentityKeyPair(): Promise<KeyPair> {
        if (!this.identityKeyPair) {
            throw new Error('Store not initialized');
        }
        return this.identityKeyPair;
    }

    async getLocalRegistrationId(): Promise<number> {
        if (!this.registrationId) {
            throw new Error('Store not initialized');
        }
        return this.registrationId;
    }

    async saveIdentity(address: string, identityKey: Uint8Array): Promise<boolean> {
        return await this.db.saveIdentity(address, identityKey);
    }

    async isTrustedIdentity(address: string, identityKey: Uint8Array): Promise<boolean> {
        return await this.db.isTrustedIdentity(address, identityKey);
    }

    // PreKey operations
    async generatePreKeys(startId: number, count: number): Promise<PreKey[]> {
        logger.info(`Generating ${count} prekeys starting from ${startId}`);

        const preKeys: PreKey[] = [];

        for (let i = 0; i < count; i++) {
            const keyId = startId + i;
            const keyPair = await CryptoUtils.generateX25519KeyPair();

            await this.db.storePreKey(keyId, keyPair);

            preKeys.push({
                keyId,
                keyPair
            });
        }

        return preKeys;
    }

    async loadPreKey(keyId: number): Promise<KeyPair> {
        const keyPair = await this.db.loadPreKey(keyId);
        if (!keyPair) {
            throw new Error(`PreKey ${keyId} not found`);
        }
        return keyPair;
    }

    async removePreKey(keyId: number): Promise<void> {
        await this.db.removePreKey(keyId);
    }

    // Signed PreKey operations
    async generateSignedPreKey(keyId: number): Promise<SignedPreKey> {
        logger.info(`Generating signed prekey ${keyId}`);

        if (!this.identityKeyPair) {
            throw new Error('Store not initialized');
        }

        const keyPair = await CryptoUtils.generateX25519KeyPair();
        const signature = await CryptoUtils.sign(keyPair.publicKey, this.identityKeyPair.privateKey);

        await this.db.storeSignedPreKey(keyId, keyPair, signature);

        return {
            keyId,
            keyPair,
            signature,
            timestamp: Date.now()
        };
    }

    async loadSignedPreKey(keyId: number): Promise<SignedPreKey> {
        const signedPreKey = await this.db.loadSignedPreKey(keyId);
        if (!signedPreKey) {
            throw new Error(`Signed PreKey ${keyId} not found`);
        }
        return signedPreKey;
    }

    // Session operations
    async storeSession(address: string, deviceId: number, session: SessionState): Promise<void> {
        await this.db.storeSession(address, deviceId, session);
    }

    async loadSession(address: string, deviceId: number): Promise<SessionState | undefined> {
        return await this.db.loadSession(address, deviceId);
    }

    async removeSession(address: string, deviceId: number): Promise<void> {
        await this.db.removeSession(address, deviceId);
    }

    async removeAllSessions(address: string): Promise<void> {
        const sessions = await this.db.sessions.where('address').equals(address).toArray();

        for (const session of sessions) {
            await this.db.sessions.delete(session.id);
        }

        logger.info(`Removed all sessions for ${address}`);
    }

    // Generate PreKey bundle for others to establish sessions with us
    async generatePreKeyBundle(): Promise<PreKeyBundle> {
        if (!this.identityKeyPair || !this.registrationId) {
            throw new Error('Store not initialized');
        }

        // Generate a new one-time prekey
        const preKey = await this.generatePreKeys(Math.floor(Math.random() * 0xFFFFFF), 1);

        // Get current signed prekey (or generate if needed)
        let signedPreKey: SignedPreKey;
        const existingSignedPreKey = await this.db.signedPreKeys.orderBy('timestamp').reverse().first();

        if (!existingSignedPreKey) {
            signedPreKey = await this.generateSignedPreKey(1);
        } else {
            signedPreKey = {
                keyId: existingSignedPreKey.keyId,
                keyPair: existingSignedPreKey.keyPair,
                signature: existingSignedPreKey.signature,
                timestamp: existingSignedPreKey.timestamp
            };
        }

        return {
            registrationId: this.registrationId,
            deviceId: 1, // Single device for now
            preKeyId: preKey[0].keyId,
            preKeyPublic: preKey[0].keyPair.publicKey,
            signedPreKeyId: signedPreKey.keyId,
            signedPreKeyPublic: signedPreKey.keyPair.publicKey,
            signedPreKeySignature: signedPreKey.signature,
            identityKey: this.identityKeyPair.publicKey
        };
    }
}