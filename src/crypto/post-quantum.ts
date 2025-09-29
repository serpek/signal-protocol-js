// ===== POST-QUANTUM CRYPTO SUPPORT =====
// src/crypto/post-quantum.ts
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { Logger } from 'tslog';
import {KeyPair} from "../types/signal.types.ts";

const logger = new Logger({ name: 'PostQuantumCrypto' });

export interface PQKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface HybridKeyPair {
    classical: KeyPair;
    postQuantum: PQKeyPair;
}

export class PostQuantumCrypto {
    /**
     * Generate ML-KEM-768 key pair for post-quantum key encapsulation
     */
    static async generateKemKeyPair(): Promise<PQKeyPair> {
        const { publicKey, secretKey } = ml_kem768.keygen();

        logger.debug('Generated ML-KEM-768 key pair');

        return {
            publicKey,
            privateKey: secretKey
        };
    }

    /**
     * Generate ML-DSA-65 key pair for post-quantum signatures
     */
    static async generateSignatureKeyPair(): Promise<PQKeyPair> {
        const { publicKey, secretKey } = ml_dsa65.keygen();

        logger.debug('Generated ML-DSA-65 key pair');

        return {
            publicKey,
            privateKey: secretKey
        };
    }

    /**
     * Encapsulate a shared secret using ML-KEM-768
     */
    static async encapsulate(publicKey: Uint8Array): Promise<{
        ciphertext: Uint8Array;
        sharedSecret: Uint8Array;
    }> {
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);

        return {
            ciphertext: cipherText,
            sharedSecret
        };
    }

    /**
     * Decapsulate a shared secret using ML-KEM-768
     */
    static async decapsulate(
        ciphertext: Uint8Array,
        privateKey: Uint8Array
    ): Promise<Uint8Array> {
        return ml_kem768.decapsulate(ciphertext, privateKey);
    }

    /**
     * Sign a message using ML-DSA-65
     */
    static async signPQ(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
        return ml_dsa65.sign(privateKey, message);
    }

    /**
     * Verify a signature using ML-DSA-65
     */
    static async verifyPQ(
        signature: Uint8Array,
        message: Uint8Array,
        publicKey: Uint8Array
    ): Promise<boolean> {
        return ml_dsa65.verify(publicKey, message, signature);
    }
}
