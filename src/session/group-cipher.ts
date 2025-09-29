
// ===== GROUP MESSAGING =====
// src/session/group-cipher.ts
import { SignalProtocolStore } from '../store/signal-store';
import { SessionCipher, CiphertextMessage } from './session-cipher';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'GroupCipher' });

export interface GroupMessage {
    groupId: string;
    senderId: string;
    message: CiphertextMessage;
    timestamp: number;
}

export class GroupCipher {
    private store: SignalProtocolStore;
    private groupId: string;
    private members: Set<string>;

    constructor(store: SignalProtocolStore, groupId: string) {
        this.store = store;
        this.groupId = groupId;
        this.members = new Set();
    }

    /**
     * Add a member to the group
     */
    async addMember(memberId: string): Promise<void> {
        this.members.add(memberId);
        logger.info(`Added member ${memberId} to group ${this.groupId}`);
    }

    /**
     * Remove a member from the group
     */
    async removeMember(memberId: string): Promise<void> {
        this.members.delete(memberId);
        logger.info(`Removed member ${memberId} from group ${this.groupId}`);
    }

    /**
     * Encrypt a message for all group members
     */
    async encrypt(plaintext: Uint8Array): Promise<Map<string, CiphertextMessage>> {
        const encrypted = new Map<string, CiphertextMessage>();

        for (const memberId of this.members) {
            const cipher = new SessionCipher(this.store, memberId);
            const ciphertext = await cipher.encrypt(plaintext);
            encrypted.set(memberId, ciphertext);
        }

        logger.info(`Encrypted message for ${this.members.size} group members`);

        return encrypted;
    }

    /**
     * Decrypt a message from a group member
     */
    async decrypt(senderId: string, message: CiphertextMessage): Promise<Uint8Array> {
        if (!this.members.has(senderId)) {
            throw new Error(`${senderId} is not a member of group ${this.groupId}`);
        }

        const cipher = new SessionCipher(this.store, senderId);
        const plaintext = await cipher.decrypt(message);

        logger.info(`Decrypted message from ${senderId} in group ${this.groupId}`);

        return plaintext;
    }

    /**
     * Get current group members
     */
    getMembers(): string[] {
        return Array.from(this.members);
    }
}
