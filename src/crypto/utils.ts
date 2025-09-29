
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { Logger } from 'tslog';
import { KeyPair } from '../types/signal.types';

const logger = new Logger({ name: 'CryptoUtils' });

export class CryptoUtils {
    static generateRandomBytes(length: number): Uint8Array {
        const bytes = new Uint8Array(length);
        crypto.getRandomValues(bytes);
        return bytes;
    }

    static async generateKeyPair(): Promise<KeyPair> {
        const privateKey = ed25519.utils.randomPrivateKey();
        const publicKey = await ed25519.getPublicKey(privateKey);

        logger.debug('Generated new key pair');

        return {
            privateKey: new Uint8Array(privateKey),
            publicKey: new Uint8Array(publicKey)
        };
    }

    static async generateX25519KeyPair(): Promise<KeyPair> {
        const privateKey = x25519.utils.randomPrivateKey();
        const publicKey = x25519.getPublicKey(privateKey);

        return {
            privateKey: new Uint8Array(privateKey),
            publicKey: new Uint8Array(publicKey)
        };
    }

    static async performDH(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
        const shared = x25519.getSharedSecret(privateKey, publicKey);
        return new Uint8Array(shared);
    }

    static async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
        const signature = ed25519.sign(message, privateKey);
        return new Uint8Array(signature);
    }

    static async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
        return ed25519.verify(signature, message, publicKey);
    }

    static async deriveSecrets(
        inputKeyMaterial: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        outputLength: number
    ): Promise<Uint8Array> {
        const derived = hkdf(sha256, inputKeyMaterial, salt, info, outputLength);
        return new Uint8Array(derived);
    }

    static async calculateMAC(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
        const mac = hmac(sha256, key, message);
        return new Uint8Array(mac);
    }

    static async encrypt(key: Uint8Array, plaintext: Uint8Array, associatedData?: Uint8Array): Promise<Uint8Array> {
        const nonce = CryptoUtils.generateRandomBytes(24);
        const cipher = chacha20poly1305(key, nonce, associatedData);
        const ciphertext = cipher.encrypt(plaintext);

        // Prepend nonce to ciphertext
        const result = new Uint8Array(nonce.length + ciphertext.length);
        result.set(nonce);
        result.set(new Uint8Array(ciphertext), nonce.length);

        return result;
    }

    static async decrypt(key: Uint8Array, ciphertextWithNonce: Uint8Array, associatedData?: Uint8Array): Promise<Uint8Array> {
        const nonce = ciphertextWithNonce.slice(0, 24);
        const ciphertext = ciphertextWithNonce.slice(24);

        const cipher = chacha20poly1305(key, nonce, associatedData);
        const plaintext = cipher.decrypt(ciphertext);
        return new Uint8Array(plaintext);
    }

    static concatArrays(...arrays: Uint8Array[]): Uint8Array {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);

        let offset = 0;
        for (const array of arrays) {
            result.set(array, offset);
            offset += array.length;
        }

        return result;
    }
}