
import * as libsignal from '@signalapp/libsignal-client';

// In-memory store implementations
class InMemorySessionStore extends libsignal.SessionStore {
    private sessions: Map<string, Buffer> = new Map();

    async saveSession(name: libsignal.ProtocolAddress, record: libsignal.SessionRecord): Promise<void> {
        const key = `${name.name()}.${name.deviceId()}`;
        this.sessions.set(key, record.serialize());
    }

    async getSession(name: libsignal.ProtocolAddress): Promise<libsignal.SessionRecord | null> {
        const key = `${name.name()}.${name.deviceId()}`;
        const data = this.sessions.get(key);
        if (!data) return null;
        return libsignal.SessionRecord.deserialize(data);
    }

    async getExistingSessions(addresses: libsignal.ProtocolAddress[]): Promise<libsignal.SessionRecord[]> {
        const results: libsignal.SessionRecord[] = [];
        for (const addr of addresses) {
            const session = await this.getSession(addr);
            if (session) results.push(session);
        }
        return results;
    }
}

class InMemoryIdentityKeyStore extends libsignal.IdentityKeyStore {
    private identities: Map<string, Uint8Array> = new Map();
    private localRegistrationId: number;
    private identityKeyPair: libsignal.PrivateKey;

    constructor(identityKey: libsignal.PrivateKey, localRegistrationId: number) {
        super();
        this.identityKeyPair = identityKey;
        this.localRegistrationId = localRegistrationId;
    }

    async getIdentityKey(): Promise<libsignal.PrivateKey> {
        return this.identityKeyPair;
    }

    async getLocalRegistrationId(): Promise<number> {
        return this.localRegistrationId;
    }

    async saveIdentity(name: libsignal.ProtocolAddress, key: libsignal.PublicKey): Promise<boolean> {
        const keyStr = `${name.name()}.${name.deviceId()}`;
        const existing = this.identities.get(keyStr);
        this.identities.set(keyStr, key.serialize());
        return !existing || !Buffer.from(existing).equals(Buffer.from(key.serialize()));
    }

    async getIdentity(name: libsignal.ProtocolAddress): Promise<libsignal.PublicKey | null> {
        const keyStr = `${name.name()}.${name.deviceId()}`;
        const data = this.identities.get(keyStr);
        if (!data) return null;
        return libsignal.PublicKey.deserialize(Buffer.from(data));
    }

    async isTrustedIdentity(
        name: libsignal.ProtocolAddress,
        key: libsignal.PublicKey,
        _direction: libsignal.Direction  // Prefix with underscore to indicate unused
    ): Promise<boolean> {
        const existing = await this.getIdentity(name);
        if (!existing) return true;
        return Buffer.from(existing.serialize()).equals(Buffer.from(key.serialize()));
    }
}

class InMemoryPreKeyStore extends libsignal.PreKeyStore {
    private preKeys: Map<number, Buffer> = new Map();

    async savePreKey(id: number, record: libsignal.PreKeyRecord): Promise<void> {
        this.preKeys.set(id, record.serialize());
    }

    async getPreKey(id: number): Promise<libsignal.PreKeyRecord> {
        const data = this.preKeys.get(id);
        if (!data) throw new Error(`PreKey ${id} not found`);
        return libsignal.PreKeyRecord.deserialize(data);
    }

    async removePreKey(id: number): Promise<void> {
        this.preKeys.delete(id);
    }
}

class InMemorySignedPreKeyStore extends libsignal.SignedPreKeyStore {
    private signedPreKeys: Map<number, Buffer> = new Map();

    async saveSignedPreKey(id: number, record: libsignal.SignedPreKeyRecord): Promise<void> {
        this.signedPreKeys.set(id, record.serialize());
    }

    async getSignedPreKey(id: number): Promise<libsignal.SignedPreKeyRecord> {
        const data = this.signedPreKeys.get(id);
        if (!data) throw new Error(`Signed PreKey ${id} not found`);
        return libsignal.SignedPreKeyRecord.deserialize(data);
    }
}

// Empty Kyber store for post-quantum support (not used in our test)
class InMemoryKyberPreKeyStore extends libsignal.KyberPreKeyStore {
    private kyberPreKeys: Map<number, Buffer> = new Map();

    async saveKyberPreKey(id: number, record: libsignal.KyberPreKeyRecord): Promise<void> {
        this.kyberPreKeys.set(id, record.serialize());
    }

    async getKyberPreKey(id: number): Promise<libsignal.KyberPreKeyRecord> {
        const data = this.kyberPreKeys.get(id);
        if (!data) throw new Error(`Kyber PreKey ${id} not found`);
        return libsignal.KyberPreKeyRecord.deserialize(data);
    }

    async markKyberPreKeyUsed(id: number): Promise<void> {
        // Mark as used (in production, you might want to delete or flag it)
        console.log(`Kyber PreKey ${id} marked as used`);
    }
}

export class LibSignalAdapter {
    private identityKeyPair: libsignal.PrivateKey;
    private registrationId: number;
    private signedPreKey: {
        keyPair: libsignal.PrivateKey;
        signature: Buffer;
        keyId: number;
    } | null = null;
    private preKeys: Map<number, libsignal.PrivateKey> = new Map();
    private sessionStore: InMemorySessionStore;
    private identityStore: InMemoryIdentityKeyStore;
    private preKeyStore: InMemoryPreKeyStore;
    private signedPreKeyStore: InMemorySignedPreKeyStore;
    private kyberPreKeyStore: InMemoryKyberPreKeyStore;

    constructor() {
        // Generate identity
        this.identityKeyPair = libsignal.PrivateKey.generate();
        this.registrationId = Math.floor(Math.random() * 16383) + 1;

        // Initialize stores
        this.sessionStore = new InMemorySessionStore();
        this.identityStore = new InMemoryIdentityKeyStore(
            this.identityKeyPair,
            this.registrationId
        );
        this.preKeyStore = new InMemoryPreKeyStore();
        this.signedPreKeyStore = new InMemorySignedPreKeyStore();
        this.kyberPreKeyStore = new InMemoryKyberPreKeyStore();
    }

    /**
     * Generate a prekey bundle for others to establish sessions
     */
    async generatePreKeyBundle(): Promise<{
        registrationId: number;
        deviceId: number;
        preKeyId: number;
        preKeyPublic: Uint8Array;
        signedPreKeyId: number;
        signedPreKeyPublic: Uint8Array;
        signedPreKeySignature: Uint8Array;
        identityKey: Uint8Array;
    }> {
        // Generate one-time prekey
        const preKeyId = Math.floor(Math.random() * 0xFFFFFF);
        const preKeyPair = libsignal.PrivateKey.generate();
        this.preKeys.set(preKeyId, preKeyPair);

        // Store prekey
        const preKeyRecord = libsignal.PreKeyRecord.new(preKeyId, preKeyPair.getPublicKey(), preKeyPair);
        await this.preKeyStore.savePreKey(preKeyId, preKeyRecord);

        // Generate signed prekey if not exists
        if (!this.signedPreKey) {
            const signedPreKeyId = 1;
            const signedKeyPair = libsignal.PrivateKey.generate();
            const signature = this.identityKeyPair.sign(signedKeyPair.getPublicKey().serialize());

            this.signedPreKey = {
                keyPair: signedKeyPair,
                signature: Buffer.from(signature),
                keyId: signedPreKeyId
            };

            // Store signed prekey
            const signedPreKeyRecord = libsignal.SignedPreKeyRecord.new(
                signedPreKeyId,
                Date.now(),
                signedKeyPair.getPublicKey(),
                signedKeyPair,
                Buffer.from(signature)
            );
            await this.signedPreKeyStore.saveSignedPreKey(signedPreKeyId, signedPreKeyRecord);
        }

        return {
            registrationId: this.registrationId,
            deviceId: 1,
            preKeyId,
            preKeyPublic: preKeyPair.getPublicKey().serialize(),
            signedPreKeyId: this.signedPreKey.keyId,
            signedPreKeyPublic: this.signedPreKey.keyPair.getPublicKey().serialize(),
            signedPreKeySignature: new Uint8Array(this.signedPreKey.signature),
            identityKey: this.identityKeyPair.getPublicKey().serialize()
        };
    }

    /**
     * Process a prekey bundle to establish a session
     */
    async processPreKeyBundle(
        recipientAddress: string,
        bundle: {
            registrationId: number;
            deviceId: number;
            preKeyId?: number;
            preKeyPublic?: Uint8Array;
            signedPreKeyId: number;
            signedPreKeyPublic: Uint8Array;
            signedPreKeySignature: Uint8Array;
            identityKey: Uint8Array;
        }
    ): Promise<void> {
        const remoteAddress = libsignal.ProtocolAddress.new(recipientAddress, bundle.deviceId);

        const preKeyPublic = bundle.preKeyPublic
            ? libsignal.PublicKey.deserialize(Buffer.from(bundle.preKeyPublic))
            : null;

        const preKeyBundle = libsignal.PreKeyBundle.new(
            bundle.registrationId,
            bundle.deviceId,
            bundle.preKeyId !== undefined ? bundle.preKeyId : null,
            preKeyPublic,
            bundle.signedPreKeyId,
            libsignal.PublicKey.deserialize(Buffer.from(bundle.signedPreKeyPublic)),
            Buffer.from(bundle.signedPreKeySignature),
            libsignal.PublicKey.deserialize(Buffer.from(bundle.identityKey))
        );

        await libsignal.processPreKeyBundle(
            preKeyBundle,
            remoteAddress,
            this.sessionStore,
            this.identityStore,
            new Date()  // Use Date object instead of timestamp
        );
    }

    /**
     * Encrypt a message
     */
    async encrypt(recipientAddress: string, deviceId: number, plaintext: string): Promise<{
        type: number;
        body: Uint8Array;
        registrationId?: number;
    }> {
        const message = Buffer.from(plaintext, 'utf-8');
        const remoteAddress = libsignal.ProtocolAddress.new(recipientAddress, deviceId);

        const ciphertext = await libsignal.signalEncrypt(
            message,
            remoteAddress,
            this.sessionStore,
            this.identityStore,
            new Date()  // Use Date object instead of timestamp
        );

        return {
            type: ciphertext.type(),
            body: new Uint8Array(ciphertext.serialize()),
            registrationId: this.registrationId
        };
    }

    /**
     * Decrypt a message
     */
    async decrypt(senderAddress: string, deviceId: number, ciphertext: {
        type: number;
        body: Uint8Array;
    }): Promise<string> {
        const remoteAddress = libsignal.ProtocolAddress.new(senderAddress, deviceId);

        let plaintext: Buffer;

        if (ciphertext.type === 3) { // PreKeyWhisperMessage
            const message = libsignal.PreKeySignalMessage.deserialize(Buffer.from(ciphertext.body));
            plaintext = await libsignal.signalDecryptPreKey(
                message,
                remoteAddress,
                this.sessionStore,
                this.identityStore,
                this.preKeyStore,
                this.signedPreKeyStore,
                this.kyberPreKeyStore,  // Add Kyber store
            );
        } else { // WhisperMessage
            const message = libsignal.SignalMessage.deserialize(Buffer.from(ciphertext.body));
            plaintext = await libsignal.signalDecrypt(
                message,
                remoteAddress,
                this.sessionStore,
                this.identityStore
                // Note: signalDecrypt only takes 4 arguments, no timestamp
            );
        }

        return plaintext.toString('utf-8');
    }

    /**
     * Get identity public key
     */
    getIdentityPublicKey(): Uint8Array {
        return this.identityKeyPair.getPublicKey().serialize();
    }
}