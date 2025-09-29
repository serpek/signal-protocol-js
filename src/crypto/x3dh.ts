
import { CryptoUtils } from './utils';
import { KeyPair, PreKeyBundle } from '../types/signal.types';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'X3DH' });

export interface X3DHResult {
    sharedSecret: Uint8Array;
    ephemeralKey: KeyPair;
    associatedData: Uint8Array;
}

export class X3DH {
    static async performInitiatorKeyAgreement(
        identityKeyPair: KeyPair,
        preKeyBundle: PreKeyBundle
    ): Promise<X3DHResult> {
        logger.info('Performing X3DH initiator key agreement');

        // Generate ephemeral key pair
        const ephemeralKeyPair = await CryptoUtils.generateX25519KeyPair();

        // Verify signature on signed pre-key
        const signedPreKeyValid = await CryptoUtils.verify(
            preKeyBundle.signedPreKeySignature,
            preKeyBundle.signedPreKeyPublic,
            preKeyBundle.identityKey
        );

        if (!signedPreKeyValid) {
            throw new Error('Invalid signed pre-key signature');
        }

        // Perform 4 DH calculations
        const dh1 = await CryptoUtils.performDH(identityKeyPair.privateKey, preKeyBundle.signedPreKeyPublic);
        const dh2 = await CryptoUtils.performDH(ephemeralKeyPair.privateKey, preKeyBundle.identityKey);
        const dh3 = await CryptoUtils.performDH(ephemeralKeyPair.privateKey, preKeyBundle.signedPreKeyPublic);

        let dh4: Uint8Array;
        if (preKeyBundle.preKeyPublic) {
            dh4 = await CryptoUtils.performDH(ephemeralKeyPair.privateKey, preKeyBundle.preKeyPublic);
        } else {
            dh4 = new Uint8Array(32);
        }

        // Concatenate DH outputs
        const dhConcat = CryptoUtils.concatArrays(dh1, dh2, dh3, dh4);

        // Derive shared secret using HKDF
        const salt = new Uint8Array(32); // All zeros
        const info = new TextEncoder().encode('Signal_X3DH_25519_ChaChaPoly_SHA256');
        const sharedSecret = await CryptoUtils.deriveSecrets(dhConcat, salt, info, 32);

        // Create associated data
        const associatedData = CryptoUtils.concatArrays(
            identityKeyPair.publicKey,
            preKeyBundle.identityKey
        );

        logger.info('X3DH key agreement completed');

        return {
            sharedSecret,
            ephemeralKey: ephemeralKeyPair,
            associatedData
        };
    }

    static async performResponderKeyAgreement(
        identityKeyPair: KeyPair,
        signedPreKeyPair: KeyPair,
        preKeyPair: KeyPair | undefined,
        remoteIdentityKey: Uint8Array,
        remoteEphemeralKey: Uint8Array
    ): Promise<X3DHResult> {
        logger.info('Performing X3DH responder key agreement');

        // Perform 4 DH calculations (matching initiator's)
        const dh1 = await CryptoUtils.performDH(signedPreKeyPair.privateKey, remoteIdentityKey);
        const dh2 = await CryptoUtils.performDH(identityKeyPair.privateKey, remoteEphemeralKey);
        const dh3 = await CryptoUtils.performDH(signedPreKeyPair.privateKey, remoteEphemeralKey);

        let dh4: Uint8Array;
        if (preKeyPair) {
            dh4 = await CryptoUtils.performDH(preKeyPair.privateKey, remoteEphemeralKey);
        } else {
            dh4 = new Uint8Array(32);
        }

        // Concatenate DH outputs
        const dhConcat = CryptoUtils.concatArrays(dh1, dh2, dh3, dh4);

        // Derive shared secret using HKDF
        const salt = new Uint8Array(32); // All zeros
        const info = new TextEncoder().encode('Signal_X3DH_25519_ChaChaPoly_SHA256');
        const sharedSecret = await CryptoUtils.deriveSecrets(dhConcat, salt, info, 32);

        // Create associated data
        const associatedData = CryptoUtils.concatArrays(
            remoteIdentityKey,
            identityKeyPair.publicKey
        );

        logger.info('X3DH responder key agreement completed');

        return {
            sharedSecret,
            ephemeralKey: { publicKey: new Uint8Array(0), privateKey: new Uint8Array(0) }, // Not used by responder
            associatedData
        };
    }
}