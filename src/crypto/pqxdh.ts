
// ===== PQXDH IMPLEMENTATION =====
// src/crypto/pqxdh.ts
import { X3DH } from './x3dh';
import { PostQuantumCrypto } from './post-quantum';
import { CryptoUtils } from './utils';
import { KeyPair, PreKeyBundle } from '../types/signal.types';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'PQXDH' });

export interface PQPreKeyBundle extends PreKeyBundle {
    kemPublicKey: Uint8Array;
    kemSignature: Uint8Array;
}

export interface PQXDHResult {
    sharedSecret: Uint8Array;
    ephemeralKey: KeyPair;
    kemCiphertext: Uint8Array;
    associatedData: Uint8Array;
}

export class PQXDH {
    /**
     * Perform PQXDH key agreement as initiator (hybrid classical + post-quantum)
     */
    static async performInitiatorKeyAgreement(
        identityKeyPair: KeyPair,
        pqBundle: PQPreKeyBundle
    ): Promise<PQXDHResult> {
        logger.info('Performing PQXDH initiator key agreement');

        // Perform classical X3DH
        const classicalResult = await X3DH.performInitiatorKeyAgreement(
            identityKeyPair,
            pqBundle
        );

        // Verify KEM public key signature
        const kemSignatureValid = await CryptoUtils.verify(
            pqBundle.kemSignature,
            pqBundle.kemPublicKey,
            pqBundle.identityKey
        );

        if (!kemSignatureValid) {
            throw new Error('Invalid KEM public key signature');
        }

        // Perform post-quantum KEM
        const { ciphertext, sharedSecret: kemSecret } = await PostQuantumCrypto.encapsulate(
            pqBundle.kemPublicKey
        );

        // Combine classical and post-quantum secrets
        const combinedInput = CryptoUtils.concatArrays(
            classicalResult.sharedSecret,
            kemSecret
        );

        // Derive final shared secret
        const salt = new Uint8Array(32);
        const info = new TextEncoder().encode('Signal_PQXDH_Hybrid');
        const hybridSecret = await CryptoUtils.deriveSecrets(
            combinedInput,
            salt,
            info,
            32
        );

        logger.info('PQXDH key agreement completed');

        return {
            sharedSecret: hybridSecret,
            ephemeralKey: classicalResult.ephemeralKey,
            kemCiphertext: ciphertext,
            associatedData: classicalResult.associatedData
        };
    }

    /**
     * Perform PQXDH key agreement as responder
     */
    static async performResponderKeyAgreement(
        identityKeyPair: KeyPair,
        signedPreKeyPair: KeyPair,
        preKeyPair: KeyPair | undefined,
        kemPrivateKey: Uint8Array,
        remoteIdentityKey: Uint8Array,
        remoteEphemeralKey: Uint8Array,
        kemCiphertext: Uint8Array
    ): Promise<PQXDHResult> {
        logger.info('Performing PQXDH responder key agreement');

        // Perform classical X3DH
        const classicalResult = await X3DH.performResponderKeyAgreement(
            identityKeyPair,
            signedPreKeyPair,
            preKeyPair,
            remoteIdentityKey,
            remoteEphemeralKey
        );

        // Decapsulate KEM ciphertext
        const kemSecret = await PostQuantumCrypto.decapsulate(
            kemCiphertext,
            kemPrivateKey
        );

        // Combine classical and post-quantum secrets
        const combinedInput = CryptoUtils.concatArrays(
            classicalResult.sharedSecret,
            kemSecret
        );

        // Derive final shared secret
        const salt = new Uint8Array(32);
        const info = new TextEncoder().encode('Signal_PQXDH_Hybrid');
        const hybridSecret = await CryptoUtils.deriveSecrets(
            combinedInput,
            salt,
            info,
            32
        );

        logger.info('PQXDH responder key agreement completed');

        return {
            sharedSecret: hybridSecret,
            ephemeralKey: classicalResult.ephemeralKey,
            kemCiphertext,
            associatedData: classicalResult.associatedData
        };
    }
}
