
export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface PreKey {
    keyId: number;
    keyPair: KeyPair;
}

export interface SignedPreKey extends PreKey {
    signature: Uint8Array;
    timestamp: number;
}

export interface PreKeyBundle {
    registrationId: number;
    deviceId: number;
    preKeyId?: number;
    preKeyPublic?: Uint8Array;
    signedPreKeyId: number;
    signedPreKeyPublic: Uint8Array;
    signedPreKeySignature: Uint8Array;
    identityKey: Uint8Array;
}

export interface SessionState {
    sessionVersion: number;
    localIdentityPublic: Uint8Array;
    remoteIdentityPublic: Uint8Array;
    rootKey: Uint8Array;
    sendingChain?: {
        senderRatchetKey: KeyPair;
        chainKey: Uint8Array;
        messageKeys: Map<number, Uint8Array>;
        index: number;
    };
    receivingChains: Array<{
        senderRatchetKey: Uint8Array;
        chainKey: Uint8Array;
        messageKeys: Map<number, Uint8Array>;
        index: number;
    }>;
    pendingPreKey?: {
        preKeyId?: number;
        signedPreKeyId: number;
        baseKey: Uint8Array;
    };
    remoteRegistrationId?: number;
    localRegistrationId?: number;
    previousCounter: number;
}

export interface MessageEnvelope {
    type: MessageType;
    senderAddress: string;
    senderDevice: number;
    timestamp: number;
    content: Uint8Array;
}

export enum MessageType {
    PLAINTEXT = 0,
    PREKEY_BUNDLE = 1,
    WHISPER = 2,
}