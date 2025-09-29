
// ===== REACT CONTEXT =====
// src/context/SignalContext.tsx
import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { SignalProtocolStore } from '../store/signal-store';
import { SessionCipher, CiphertextMessage } from '../session/session-cipher';
import { PreKeyBundle } from '../types/signal.types';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'SignalContext' });

interface SignalContextType {
    store: SignalProtocolStore | null;
    isInitialized: boolean;
    sendMessage: (recipientId: string, message: string) => Promise<CiphertextMessage>;
    receiveMessage: (senderId: string, message: CiphertextMessage) => Promise<string>;
    establishSession: (recipientId: string, preKeyBundle: PreKeyBundle) => Promise<void>;
    getPreKeyBundle: () => Promise<PreKeyBundle>;
    exportIdentity: () => Promise<{ publicKey: string; privateKey: string }>;
}

const SignalContext = createContext<SignalContextType | null>(null);

interface SignalProviderProps {
    children: ReactNode;
    encryptionPassword?: string;
}

export function SignalProvider({ children, encryptionPassword }: SignalProviderProps) {
    const [store, setStore] = useState<SignalProtocolStore | null>(null);
    const [isInitialized, setIsInitialized] = useState(false);

    useEffect(() => {
        const initSignal = async () => {
            try {
                logger.info('Initializing Signal Protocol');

                const signalStore = new SignalProtocolStore();

                // Derive encryption key from password if provided
                let encryptionKey: Uint8Array | undefined;
                if (encryptionPassword) {
                    const encoder = new TextEncoder();
                    const passwordBuffer = encoder.encode(encryptionPassword);

                    const hashBuffer = await crypto.subtle.digest('SHA-256', passwordBuffer);
                    encryptionKey = new Uint8Array(hashBuffer);
                }

                await signalStore.initialize(encryptionKey);

                setStore(signalStore);
                setIsInitialized(true);

                logger.info('Signal Protocol initialized successfully');
            } catch (error) {
                logger.error('Failed to initialize Signal Protocol:', error);
            }
        };

        initSignal();
    }, [encryptionPassword]);

    const sendMessage = async (recipientId: string, message: string): Promise<CiphertextMessage> => {
        if (!store) throw new Error('Signal store not initialized');

        const sessionCipher = new SessionCipher(store, recipientId);
        const plaintext = new TextEncoder().encode(message);
        const ciphertext = await sessionCipher.encrypt(plaintext);

        logger.info(`Message sent to ${recipientId}`);

        return ciphertext;
    };

    const receiveMessage = async (senderId: string, message: CiphertextMessage): Promise<string> => {
        if (!store) throw new Error('Signal store not initialized');

        const sessionCipher = new SessionCipher(store, senderId);
        const plaintext = await sessionCipher.decrypt(message);

        logger.info(`Message received from ${senderId}`);

        return new TextDecoder().decode(plaintext);
    };

    const establishSession = async (recipientId: string, preKeyBundle: PreKeyBundle): Promise<void> => {
        if (!store) throw new Error('Signal store not initialized');

        const sessionCipher = new SessionCipher(store, recipientId);
        await sessionCipher.processPreKeyBundle(preKeyBundle);

        logger.info(`Session established with ${recipientId}`);
    };

    const getPreKeyBundle = async (): Promise<PreKeyBundle> => {
        if (!store) throw new Error('Signal store not initialized');

        return await store.generatePreKeyBundle();
    };

    const exportIdentity = async (): Promise<{ publicKey: string; privateKey: string }> => {
        if (!store) throw new Error('Signal store not initialized');

        const keyPair = await store.getIdentityKeyPair();

        return {
            publicKey: btoa(String.fromCharCode(...keyPair.publicKey)),
            privateKey: btoa(String.fromCharCode(...keyPair.privateKey))
        };
    };

    const value: SignalContextType = {
        store,
        isInitialized,
        sendMessage,
        receiveMessage,
        establishSession,
        getPreKeyBundle,
        exportIdentity
    };

    return (
        <SignalContext.Provider value={value}>
            {children}
        </SignalContext.Provider>
    );
}

export function useSignal(): SignalContextType {
    const context = useContext(SignalContext);
    if (!context) {
        throw new Error('useSignal must be used within a SignalProvider');
    }
    return context;
}
