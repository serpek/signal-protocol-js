
import Dexie, { Table } from 'dexie';
import { KeyPair, SignedPreKey, SessionState } from '../types/signal.types';
import { Logger } from 'tslog';
import {applyEncryptionMiddleware, clearAllTables} from "dexie-encrypted";

const logger = new Logger({ name: 'SignalDatabase' });

export interface StoredSession {
    id: string;
    address: string;
    deviceId: number;
    state: SessionState;
    timestamp: number;
}

export interface StoredPreKey {
    keyId: number;
    keyPair: KeyPair;
    timestamp: number;
}

export interface StoredSignedPreKey extends StoredPreKey {
    signature: Uint8Array;
}

export interface StoredIdentity {
    address: string;
    publicKey: Uint8Array;
    trustLevel: number;
    timestamp: number;
}

export class SignalDatabase extends Dexie {
    sessions!: Table<StoredSession>;
    preKeys!: Table<StoredPreKey>;
    signedPreKeys!: Table<StoredSignedPreKey>;
    identities!: Table<StoredIdentity>;
    metadata!: Table<any>;

    constructor() {
        super('SignalProtocolDB');

        this.version(1).stores({
            sessions: '&id, address, deviceId, timestamp',
            preKeys: '&keyId, timestamp',
            signedPreKeys: '&keyId, timestamp',
            identities: '&address, timestamp',
            metadata: '&key'
        });
    }

    async initialize(encryptionKey?: Uint8Array): Promise<void> {
        logger.info('Initializing Signal database', encryptionKey);

        if (encryptionKey) {
            applyEncryptionMiddleware(this, encryptionKey, {
            }, clearAllTables);
        }

        await this.open();
        logger.info('Database initialized successfully');
    }

    // Session operations
    async storeSession(address: string, deviceId: number, session: SessionState): Promise<void> {
        const id = `${address}.${deviceId}`;
        await this.sessions.put({
            id,
            address,
            deviceId,
            state: session,
            timestamp: Date.now()
        });

        logger.debug(`Stored session for ${id}`);
    }

    async loadSession(address: string, deviceId: number): Promise<SessionState | undefined> {
        const id = `${address}.${deviceId}`;
        const session = await this.sessions.get(id);

        if (session) {
            logger.debug(`Loaded session for ${id}`);
            return session.state;
        }

        return undefined;
    }

    async removeSession(address: string, deviceId: number): Promise<void> {
        const id = `${address}.${deviceId}`;
        await this.sessions.delete(id);
        logger.debug(`Removed session for ${id}`);
    }

    // PreKey operations
    async storePreKey(keyId: number, keyPair: KeyPair): Promise<void> {
        await this.preKeys.put({
            keyId,
            keyPair,
            timestamp: Date.now()
        });

        logger.debug(`Stored prekey ${keyId}`);
    }

    async loadPreKey(keyId: number): Promise<KeyPair | undefined> {
        const preKey = await this.preKeys.get(keyId);
        return preKey?.keyPair;
    }

    async removePreKey(keyId: number): Promise<void> {
        await this.preKeys.delete(keyId);
        logger.debug(`Removed prekey ${keyId}`);
    }

    // Signed PreKey operations
    async storeSignedPreKey(keyId: number, keyPair: KeyPair, signature: Uint8Array): Promise<void> {
        await this.signedPreKeys.put({
            keyId,
            keyPair,
            signature,
            timestamp: Date.now()
        });

        logger.debug(`Stored signed prekey ${keyId}`);
    }

    async loadSignedPreKey(keyId: number): Promise<SignedPreKey | undefined> {
        const signedPreKey = await this.signedPreKeys.get(keyId);
        if (!signedPreKey) return undefined;

        return {
            keyId: signedPreKey.keyId,
            keyPair: signedPreKey.keyPair,
            signature: signedPreKey.signature,
            timestamp: signedPreKey.timestamp
        };
    }

    // Identity operations
    async saveIdentity(address: string, publicKey: Uint8Array): Promise<boolean> {
        const existing = await this.identities.get(address);

        if (existing && !this.equalArrays(existing.publicKey, publicKey)) {
            logger.warn(`Identity key changed for ${address}`);
            // In production, this should trigger a security warning
        }

        await this.identities.put({
            address,
            publicKey,
            trustLevel: existing ? existing.trustLevel : 0,
            timestamp: Date.now()
        });

        return true;
    }

    async isTrustedIdentity(address: string, publicKey: Uint8Array): Promise<boolean> {
        const identity = await this.identities.get(address);

        if (!identity) {
            // First time seeing this identity
            return true;
        }

        return this.equalArrays(identity.publicKey, publicKey);
    }

    // Metadata operations
    async getLocalRegistrationId(): Promise<number> {
        let regId = await this.metadata.get('registrationId');

        if (!regId) {
            regId = { key: 'registrationId', value: Math.floor(Math.random() * 16383) + 1 };
            await this.metadata.put(regId);
        }

        return regId.value;
    }

    async getIdentityKeyPair(): Promise<KeyPair | undefined> {
        const identity = await this.metadata.get('identityKeyPair');
        return identity?.value;
    }

    async setIdentityKeyPair(keyPair: KeyPair): Promise<void> {
        await this.metadata.put({
            key: 'identityKeyPair',
            value: keyPair
        });
    }

    private equalArrays(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
}