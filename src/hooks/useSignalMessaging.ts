
// ===== REACT HOOKS =====
// src/hooks/useSignalMessaging.ts
import { useState, useCallback } from 'react';
import { useSignal } from '../context/SignalContext';
import { CiphertextMessage } from '../session/session-cipher';
import { PreKeyBundle } from '../types/signal.types';

export interface Message {
    id: string;
    senderId: string;
    recipientId: string;
    content: string;
    timestamp: number;
    encrypted: boolean;
}

export function useSignalMessaging() {
    const signal = useSignal();
    const [messages, setMessages] = useState<Message[]>([]);
    const [sessions, setSessions] = useState<Set<string>>(new Set());

    const sendMessage = useCallback(async (recipientId: string, content: string) => {
        if (!signal.isInitialized) {
            throw new Error('Signal not initialized');
        }

        try {
            const encrypted = await signal.sendMessage(recipientId, content);

            const message: Message = {
                id: crypto.randomUUID(),
                senderId: 'me',
                recipientId,
                content,
                timestamp: Date.now(),
                encrypted: true
            };

            setMessages(prev => [...prev, message]);

            return encrypted;
        } catch (error) {
            console.error('Failed to send message:', error);
            throw error;
        }
    }, [signal]);

    const receiveMessage = useCallback(async (
        senderId: string,
        encryptedMessage: CiphertextMessage
    ): Promise<Message> => {
        if (!signal.isInitialized) {
            throw new Error('Signal not initialized');
        }

        try {
            const content = await signal.receiveMessage(senderId, encryptedMessage);

            const message: Message = {
                id: crypto.randomUUID(),
                senderId,
                recipientId: 'me',
                content,
                timestamp: Date.now(),
                encrypted: true
            };

            setMessages(prev => [...prev, message]);

            return message;
        } catch (error) {
            console.error('Failed to receive message:', error);
            throw error;
        }
    }, [signal]);

    const establishSession = useCallback(async (
        recipientId: string,
        preKeyBundle: PreKeyBundle
    ) => {
        if (!signal.isInitialized) {
            throw new Error('Signal not initialized');
        }

        try {
            await signal.establishSession(recipientId, preKeyBundle);
            setSessions(prev => new Set(prev).add(recipientId));
        } catch (error) {
            console.error('Failed to establish session:', error);
            throw error;
        }
    }, [signal]);

    const hasSession = useCallback((recipientId: string): boolean => {
        return sessions.has(recipientId);
    }, [sessions]);

    const clearMessages = useCallback(() => {
        setMessages([]);
    }, []);

    return {
        messages,
        sessions: Array.from(sessions),
        sendMessage,
        receiveMessage,
        establishSession,
        hasSession,
        clearMessages,
        isInitialized: signal.isInitialized
    };
}
