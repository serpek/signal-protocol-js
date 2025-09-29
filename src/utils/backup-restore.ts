
// ===== BACKUP AND RESTORE =====
// src/utils/backup-restore.ts
import { SignalProtocolStore } from '../store/signal-store';
import { SignalDatabase } from '../storage/signal-database';
import { CryptoUtils } from '../crypto/utils';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'BackupRestore' });

export interface BackupData {
    version: string;
    timestamp: number;
    identityKeyPair: {
        publicKey: string;
        privateKey: string;
    };
    registrationId: number;
    sessions: Array<{
        address: string;
        deviceId: number;
        session: any;
    }>;
    preKeys: Array<{
        keyId: number;
        keyPair: {
            publicKey: string;
            privateKey: string;
        };
    }>;
    signedPreKeys: Array<{
        keyId: number;
        keyPair: {
            publicKey: string;
            privateKey: string;
        };
        signature: string;
        timestamp: number;
    }>;
    identities: Array<{
        address: string;
        publicKey: string;
        trustLevel: number;
    }>;
}

export class BackupRestore {
    /**
     * Create an encrypted backup of the Signal store
     */
    static async createBackup(
        store: SignalProtocolStore,
        backupPassword: string
    ): Promise<string> {
        logger.info('Creating encrypted backup');

        try {
            // Get all data from store
            const identityKeyPair = await store.getIdentityKeyPair();
            const registrationId = await store.getLocalRegistrationId();

            // Access database directly for bulk export
            const db = (store as any).db as SignalDatabase;

            const sessions = await db.sessions.toArray();
            const preKeys = await db.preKeys.toArray();
            const signedPreKeys = await db.signedPreKeys.toArray();
            const identities = await db.identities.toArray();

            // Create backup object
            const backup: BackupData = {
                version: '1.0.0',
                timestamp: Date.now(),
                identityKeyPair: {
                    publicKey: btoa(String.fromCharCode(...identityKeyPair.publicKey)),
                    privateKey: btoa(String.fromCharCode(...identityKeyPair.privateKey))
                },
                registrationId,
                sessions: sessions.map(s => ({
                    address: s.address,
                    deviceId: s.deviceId,
                    session: s.state
                })),
                preKeys: preKeys.map(pk => ({
                    keyId: pk.keyId,
                    keyPair: {
                        publicKey: btoa(String.fromCharCode(...pk.keyPair.publicKey)),
                        privateKey: btoa(String.fromCharCode(...pk.keyPair.privateKey))
                    }
                })),
                signedPreKeys: signedPreKeys.map(spk => ({
                    keyId: spk.keyId,
                    keyPair: {
                        publicKey: btoa(String.fromCharCode(...spk.keyPair.publicKey)),
                        privateKey: btoa(String.fromCharCode(...spk.keyPair.privateKey))
                    },
                    signature: btoa(String.fromCharCode(...spk.signature)),
                    timestamp: spk.timestamp
                })),
                identities: identities.map(id => ({
                    address: id.address,
                    publicKey: btoa(String.fromCharCode(...id.publicKey)),
                    trustLevel: id.trustLevel
                }))
            };

            // Serialize backup
            const backupJson = JSON.stringify(backup);
            const backupBytes = new TextEncoder().encode(backupJson);

            // Derive encryption key from password
            const salt = new Uint8Array(32);
            crypto.getRandomValues(salt);

            const passwordKey = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(backupPassword),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                passwordKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );

            const derivedKeyBytes = await crypto.subtle.exportKey('raw', derivedKey);
            const encryptionKey = new Uint8Array(derivedKeyBytes);

            // Encrypt backup
            const encrypted = await CryptoUtils.encrypt(encryptionKey, backupBytes);

            // Combine salt and encrypted data
            const result = new Uint8Array(salt.length + encrypted.length);
            result.set(salt);
            result.set(encrypted, salt.length);

            // Return base64 encoded backup
            const finalBackup = btoa(String.fromCharCode(...result));

            logger.info('Backup created successfully');

            return finalBackup;
        } catch (error) {
            logger.error('Failed to create backup:', error);
            throw error;
        }
    }

    /**
     * Restore from an encrypted backup
     */
    static async restoreBackup(
        store: SignalProtocolStore,
        encryptedBackup: string,
        backupPassword: string
    ): Promise<void> {
        logger.info('Restoring from encrypted backup');

        try {
            // Decode backup
            const backupBytes = Uint8Array.from(atob(encryptedBackup), c => c.charCodeAt(0));

            // Extract salt and encrypted data
            const salt = backupBytes.slice(0, 32);
            const encrypted = backupBytes.slice(32);

            // Derive decryption key
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(backupPassword),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                passwordKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            const derivedKeyBytes = await crypto.subtle.exportKey('raw', derivedKey);
            const decryptionKey = new Uint8Array(derivedKeyBytes);

            // Decrypt backup
            const decrypted = await CryptoUtils.decrypt(decryptionKey, encrypted);

            // Parse backup
            const backupJson = new TextDecoder().decode(decrypted);
            const backup = JSON.parse(backupJson) as BackupData;

            logger.info(`Restoring backup from ${new Date(backup.timestamp).toISOString()}`);

            // Access database directly
            const db = (store as any).db as SignalDatabase;

            // Clear existing data
            await db.sessions.clear();
            await db.preKeys.clear();
            await db.signedPreKeys.clear();
            await db.identities.clear();

            // Restore identity key pair
            const identityKeyPair = {
                publicKey: Uint8Array.from(atob(backup.identityKeyPair.publicKey), c => c.charCodeAt(0)),
                privateKey: Uint8Array.from(atob(backup.identityKeyPair.privateKey), c => c.charCodeAt(0))
            };

            await db.setIdentityKeyPair(identityKeyPair);

            // Restore registration ID
            await db.metadata.put({
                key: 'registrationId',
                value: backup.registrationId
            });

            // Restore sessions
            for (const session of backup.sessions) {
                await db.storeSession(session.address, session.deviceId, session.session);
            }

            // Restore prekeys
            for (const preKey of backup.preKeys) {
                await db.storePreKey(preKey.keyId, {
                    publicKey: Uint8Array.from(atob(preKey.keyPair.publicKey), c => c.charCodeAt(0)),
                    privateKey: Uint8Array.from(atob(preKey.keyPair.privateKey), c => c.charCodeAt(0))
                });
            }

            // Restore signed prekeys
            for (const signedPreKey of backup.signedPreKeys) {
                await db.storeSignedPreKey(
                    signedPreKey.keyId,
                    {
                        publicKey: Uint8Array.from(atob(signedPreKey.keyPair.publicKey), c => c.charCodeAt(0)),
                        privateKey: Uint8Array.from(atob(signedPreKey.keyPair.privateKey), c => c.charCodeAt(0))
                    },
                    Uint8Array.from(atob(signedPreKey.signature), c => c.charCodeAt(0))
                );
            }

            // Restore identities
            for (const identity of backup.identities) {
                await db.saveIdentity(
                    identity.address,
                    Uint8Array.from(atob(identity.publicKey), c => c.charCodeAt(0))
                );
            }

            logger.info('Backup restored successfully');
        } catch (error) {
            logger.error('Failed to restore backup:', error);
            throw error;
        }
    }
}