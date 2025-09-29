
import { Logger } from 'tslog';

const logger = new Logger({ name: 'ProtobufWrapper' });

// Simple protobuf encoding/decoding without external dependencies
export class ProtobufWrapper {
    /**
     * Encode a WhisperMessage
     */
    static encodeWhisperMessage(
        ephemeralKey: Uint8Array,
        counter: number,
        previousCounter: number,
        ciphertext: Uint8Array
    ): Uint8Array {
        // Simple binary encoding
        const totalLength = 4 + 4 + 4 + 32 + 4 + ciphertext.length;
        const buffer = new ArrayBuffer(totalLength);
        const view = new DataView(buffer);
        const bytes = new Uint8Array(buffer);

        let offset = 0;

        // Message type identifier
        view.setUint32(offset, 1, true); // WhisperMessage type
        offset += 4;

        // Counter
        view.setUint32(offset, counter, true);
        offset += 4;

        // Previous counter
        view.setUint32(offset, previousCounter, true);
        offset += 4;

        // Ephemeral key (32 bytes)
        bytes.set(ephemeralKey.slice(0, 32), offset);
        offset += 32;

        // Ciphertext length
        view.setUint32(offset, ciphertext.length, true);
        offset += 4;

        // Ciphertext
        bytes.set(ciphertext, offset);

        logger.debug(`Encoded WhisperMessage, size: ${bytes.length} bytes`);

        return bytes;
    }

    /**
     * Decode a WhisperMessage
     */
    static decodeWhisperMessage(data: Uint8Array): {
        ephemeralKey: Uint8Array;
        counter: number;
        previousCounter: number;
        ciphertext: Uint8Array;
    } {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let offset = 4; // Skip message type

        // Counter
        const counter = view.getUint32(offset, true);
        offset += 4;

        // Previous counter
        const previousCounter = view.getUint32(offset, true);
        offset += 4;

        // Ephemeral key
        const ephemeralKey = data.slice(offset, offset + 32);
        offset += 32;

        // Ciphertext length
        const ciphertextLength = view.getUint32(offset, true);
        offset += 4;

        // Ciphertext
        const ciphertext = data.slice(offset, offset + ciphertextLength);

        return {
            ephemeralKey,
            counter,
            previousCounter,
            ciphertext
        };
    }

    /**
     * Encode a PreKeyWhisperMessage
     */
    static encodePreKeyWhisperMessage(
        registrationId: number,
        preKeyId: number | undefined,
        signedPreKeyId: number,
        baseKey: Uint8Array,
        identityKey: Uint8Array,
        message: Uint8Array
    ): Uint8Array {
        // Calculate total length
        const hasPreKey = preKeyId !== undefined;
        const totalLength = 4 + 4 + 1 + (hasPreKey ? 4 : 0) + 4 + 32 + 32 + 4 + message.length;

        const buffer = new ArrayBuffer(totalLength);
        const view = new DataView(buffer);
        const bytes = new Uint8Array(buffer);

        let offset = 0;

        // Message type identifier
        view.setUint32(offset, 3, true); // PreKeyWhisperMessage type
        offset += 4;

        // Registration ID
        view.setUint32(offset, registrationId, true);
        offset += 4;

        // Has prekey flag
        view.setUint8(offset, hasPreKey ? 1 : 0);
        offset += 1;

        // PreKey ID (if present)
        if (hasPreKey && preKeyId !== undefined) {
            view.setUint32(offset, preKeyId, true);
            offset += 4;
        }

        // Signed PreKey ID
        view.setUint32(offset, signedPreKeyId, true);
        offset += 4;

        // Base key (32 bytes)
        bytes.set(baseKey.slice(0, 32), offset);
        offset += 32;

        // Identity key (32 bytes)
        bytes.set(identityKey.slice(0, 32), offset);
        offset += 32;

        // Message length
        view.setUint32(offset, message.length, true);
        offset += 4;

        // Message
        bytes.set(message, offset);

        logger.debug(`Encoded PreKeyWhisperMessage, size: ${bytes.length} bytes`);

        return bytes;
    }

    /**
     * Decode a PreKeyWhisperMessage
     */
    static decodePreKeyWhisperMessage(data: Uint8Array): {
        registrationId: number;
        preKeyId?: number;
        signedPreKeyId: number;
        baseKey: Uint8Array;
        identityKey: Uint8Array;
        message: Uint8Array;
    } {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let offset = 4; // Skip message type

        // Registration ID
        const registrationId = view.getUint32(offset, true);
        offset += 4;

        // Has prekey flag
        const hasPreKey = view.getUint8(offset) === 1;
        offset += 1;

        // PreKey ID (if present)
        let preKeyId: number | undefined;
        if (hasPreKey) {
            preKeyId = view.getUint32(offset, true);
            offset += 4;
        }

        // Signed PreKey ID
        const signedPreKeyId = view.getUint32(offset, true);
        offset += 4;

        // Base key
        const baseKey = data.slice(offset, offset + 32);
        offset += 32;

        // Identity key
        const identityKey = data.slice(offset, offset + 32);
        offset += 32;

        // Message length
        const messageLength = view.getUint32(offset, true);
        offset += 4;

        // Message
        const message = data.slice(offset, offset + messageLength);

        return {
            registrationId,
            preKeyId,
            signedPreKeyId,
            baseKey,
            identityKey,
            message
        };
    }
}
