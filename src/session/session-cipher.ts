
import { SignalProtocolStore } from '../store/signal-store';
import { X3DH } from '../crypto/x3dh';
import { DoubleRatchet, RatchetHeader } from '../crypto/double-ratchet';
import { CryptoUtils } from '../crypto/utils';
import { PreKeyBundle, SessionState, MessageType } from '../types/signal.types';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'SessionCipher' });

export interface CiphertextMessage {
    type: MessageType;
    body: Uint8Array;
    registrationId?: number;
    preKeyId?: number;
    signedPreKeyId?: number;
    baseKey?: Uint8Array;
    identityKey?: Uint8Array;
}

export class SessionCipher {
    protected store: SignalProtocolStore;
    protected recipientAddress: string;
    protected deviceId: number;

    constructor(store: SignalProtocolStore, recipientAddress: string, deviceId: number = 1) {
        this.store = store;
        this.recipientAddress = recipientAddress;
        this.deviceId = deviceId;
    }

    getRecipientAddress(): string {
        return this.recipientAddress;
    }

    async processPreKeyBundle(preKeyBundle: PreKeyBundle): Promise<void> {
        logger.info(`Processing prekey bundle for ${this.recipientAddress}`);

        // Save recipient's identity
        await this.store.saveIdentity(this.recipientAddress, preKeyBundle.identityKey);

        // Verify trust
        const isTrusted = await this.store.isTrustedIdentity(
            this.recipientAddress,
            preKeyBundle.identityKey
        );

        if (!isTrusted) {
            throw new Error('Untrusted identity key');
        }

        // Perform X3DH key agreement
        const identityKeyPair = await this.store.getIdentityKeyPair();
        const x3dhResult = await X3DH.performInitiatorKeyAgreement(
            identityKeyPair,
            preKeyBundle
        );

        // Initialize session
        const ratchet = new DoubleRatchet();
        await ratchet.initializeAsSender(
            x3dhResult.sharedSecret,
            preKeyBundle.signedPreKeyPublic
        );

        // Create session state
        const sessionState: SessionState = {
            sessionVersion: 3,
            localIdentityPublic: identityKeyPair.publicKey,
            remoteIdentityPublic: preKeyBundle.identityKey,
            rootKey: ratchet.exportState().RK,
            previousCounter: 0,
            sendingChain: {
                senderRatchetKey: ratchet.exportState().DHs!,
                chainKey: ratchet.exportState().CKs!,
                messageKeys: new Map(),
                index: 0
            },
            receivingChains: [],
            pendingPreKey: {
                preKeyId: preKeyBundle.preKeyId,
                signedPreKeyId: preKeyBundle.signedPreKeyId,
                baseKey: x3dhResult.ephemeralKey.publicKey
            },
            remoteRegistrationId: preKeyBundle.registrationId,
            localRegistrationId: await this.store.getLocalRegistrationId()
        };

        // Store session
        await this.store.storeSession(this.recipientAddress, this.deviceId, sessionState);

        logger.info(`Session established with ${this.recipientAddress}`);
    }

    async encrypt(plaintext: Uint8Array): Promise<CiphertextMessage> {
        const session = await this.store.loadSession(this.recipientAddress, this.deviceId);

        if (!session) {
            throw new Error(`No session found for ${this.recipientAddress}`);
        }

        // Create or restore ratchet
        const ratchet = new DoubleRatchet();
        ratchet.importState({
            DHs: session.sendingChain?.senderRatchetKey,
            DHr: session.receivingChains[0]?.senderRatchetKey,
            RK: session.rootKey,
            CKs: session.sendingChain?.chainKey,
            CKr: session.receivingChains[0]?.chainKey,
            Ns: session.sendingChain?.index || 0,
            Nr: session.receivingChains[0]?.index || 0,
            PN: session.previousCounter,
            MKSKIPPED: new Map()
        });

        // Create associated data
        const associatedData = CryptoUtils.concatArrays(
            session.localIdentityPublic,
            session.remoteIdentityPublic
        );

        // Encrypt message
        const [header, ciphertext] = await ratchet.encrypt(plaintext, associatedData);

        // Update session state
        const newState = ratchet.exportState();
        session.rootKey = newState.RK;
        if (newState.CKs && newState.DHs) {
            session.sendingChain = {
                senderRatchetKey: newState.DHs,
                chainKey: newState.CKs,
                messageKeys: new Map(),
                index: newState.Ns
            };
        }
        session.previousCounter = newState.PN;

        await this.store.storeSession(this.recipientAddress, this.deviceId, session);

        // Determine message type
        const messageType = session.pendingPreKey ? MessageType.PREKEY_BUNDLE : MessageType.WHISPER;

        // Build ciphertext message
        const message: CiphertextMessage = {
            type: messageType,
            body: this.serializeWhisperMessage(header, ciphertext)
        };

        // Include prekey information if this is the first message
        if (session.pendingPreKey) {
            message.registrationId = session.localRegistrationId;
            message.preKeyId = session.pendingPreKey.preKeyId;
            message.signedPreKeyId = session.pendingPreKey.signedPreKeyId;
            message.baseKey = session.pendingPreKey.baseKey;
            message.identityKey = session.localIdentityPublic;

            // Clear pending prekey after first message
            delete session.pendingPreKey;
            await this.store.storeSession(this.recipientAddress, this.deviceId, session);
        }

        logger.debug(`Encrypted message for ${this.recipientAddress}`);

        return message;
    }

    async decrypt(message: CiphertextMessage): Promise<Uint8Array> {
        // Handle prekey message
        if (message.type === MessageType.PREKEY_BUNDLE) {
            await this.processPreKeyMessage(message);
        }

        // Load session
        const session = await this.store.loadSession(this.recipientAddress, this.deviceId);

        if (!session) {
            throw new Error(`No session found for ${this.recipientAddress}`);
        }

        // Parse whisper message
        const { header, ciphertext } = this.parseWhisperMessage(message.body);

        // Create or restore ratchet
        const ratchet = new DoubleRatchet();
        ratchet.importState({
            DHs: session.sendingChain?.senderRatchetKey,
            DHr: session.receivingChains[0]?.senderRatchetKey,
            RK: session.rootKey,
            CKs: session.sendingChain?.chainKey,
            CKr: session.receivingChains[0]?.chainKey,
            Ns: session.sendingChain?.index || 0,
            Nr: session.receivingChains[0]?.index || 0,
            PN: session.previousCounter,
            MKSKIPPED: new Map()
        });

        // Create associated data
        const associatedData = CryptoUtils.concatArrays(
            session.remoteIdentityPublic,
            session.localIdentityPublic
        );

        // Decrypt message
        const plaintext = await ratchet.decrypt(header, ciphertext, associatedData);

        // Update session state
        const newState = ratchet.exportState();
        session.rootKey = newState.RK;

        if (newState.CKr && newState.DHr) {
            // Update or add receiving chain
            const chainIndex = session.receivingChains.findIndex(
                chain => this.equalArrays(chain.senderRatchetKey, newState.DHr!)
            );

            if (chainIndex >= 0) {
                session.receivingChains[chainIndex] = {
                    senderRatchetKey: newState.DHr,
                    chainKey: newState.CKr,
                    messageKeys: new Map(),
                    index: newState.Nr
                };
            } else {
                session.receivingChains.unshift({
                    senderRatchetKey: newState.DHr,
                    chainKey: newState.CKr,
                    messageKeys: new Map(),
                    index: newState.Nr
                });

                // Limit number of receiving chains
                if (session.receivingChains.length > 5) {
                    session.receivingChains.pop();
                }
            }
        }

        await this.store.storeSession(this.recipientAddress, this.deviceId, session);

        logger.debug(`Decrypted message from ${this.recipientAddress}`);

        return plaintext;
    }

    private async processPreKeyMessage(message: CiphertextMessage): Promise<void> {
        if (!message.baseKey || !message.identityKey ||
            message.signedPreKeyId === undefined) {
            throw new Error('Invalid prekey message');
        }

        logger.info(`Processing prekey message from ${this.recipientAddress}`);

        // Verify and save identity
        await this.store.saveIdentity(this.recipientAddress, message.identityKey);

        const isTrusted = await this.store.isTrustedIdentity(
            this.recipientAddress,
            message.identityKey
        );

        if (!isTrusted) {
            throw new Error('Untrusted identity key');
        }

        // Load our keys
        const identityKeyPair = await this.store.getIdentityKeyPair();
        const signedPreKey = await this.store.loadSignedPreKey(message.signedPreKeyId);

        let preKeyPair;
        if (message.preKeyId !== undefined) {
            preKeyPair = await this.store.loadPreKey(message.preKeyId);
        }

        // Perform X3DH as responder
        const x3dhResult = await X3DH.performResponderKeyAgreement(
            identityKeyPair,
            signedPreKey.keyPair,
            preKeyPair ? { publicKey: preKeyPair.publicKey, privateKey: preKeyPair.privateKey } : undefined,
            message.identityKey,
            message.baseKey
        );

        // Initialize ratchet as receiver
        const ratchet = new DoubleRatchet();
        await ratchet.initializeAsReceiver(
            x3dhResult.sharedSecret,
            signedPreKey.keyPair
        );

        // Create session state
        const sessionState: SessionState = {
            sessionVersion: 3,
            localIdentityPublic: identityKeyPair.publicKey,
            remoteIdentityPublic: message.identityKey,
            rootKey: ratchet.exportState().RK,
            previousCounter: 0,
            sendingChain: undefined,
            receivingChains: [],
            remoteRegistrationId: message.registrationId,
            localRegistrationId: await this.store.getLocalRegistrationId()
        };

        // Store session
        await this.store.storeSession(this.recipientAddress, this.deviceId, sessionState);

        // Remove used one-time prekey
        if (message.preKeyId !== undefined) {
            await this.store.removePreKey(message.preKeyId);
        }

        logger.info(`Session established from prekey message with ${this.recipientAddress}`);
    }

    private serializeWhisperMessage(header: RatchetHeader, ciphertext: Uint8Array): Uint8Array {
        const headerSize = 32 + 4 + 4; // publicKey + previousCounter + counter
        const result = new Uint8Array(headerSize + ciphertext.length);

        result.set(header.publicKey, 0);
        const view = new DataView(result.buffer);
        view.setUint32(32, header.previousCounter, true);
        view.setUint32(36, header.counter, true);
        result.set(ciphertext, headerSize);

        return result;
    }

    private parseWhisperMessage(body: Uint8Array): { header: RatchetHeader; ciphertext: Uint8Array } {
        const publicKey = body.slice(0, 32);
        const view = new DataView(body.buffer, body.byteOffset);
        const previousCounter = view.getUint32(32, true);
        const counter = view.getUint32(36, true);
        const ciphertext = body.slice(40);

        return {
            header: {
                publicKey,
                previousCounter,
                counter
            },
            ciphertext
        };
    }

    private equalArrays(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
}
