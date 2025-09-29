
// ===== WEBSOCKET TRANSPORT =====
// src/transport/websocket-transport.ts
import { CiphertextMessage } from '../session/session-cipher';
import { Logger } from 'tslog';

const logger = new Logger({ name: 'WebSocketTransport' });

export interface SignalWebSocketMessage {
    type: 'message' | 'prekey_bundle' | 'receipt' | 'typing';
    from: string;
    to: string;
    deviceId: number;
    timestamp: number;
    data: any;
}

export class WebSocketTransport {
    private ws: WebSocket | null = null;
    private messageQueue: SignalWebSocketMessage[] = [];
    private reconnectAttempts = 0;
    private readonly maxReconnectAttempts = 5;
    private readonly reconnectDelay = 1000;

    constructor(
        private url: string,
        private onMessage: (message: SignalWebSocketMessage) => void,
        private onConnect?: () => void,
        private onDisconnect?: () => void
    ) {}

    /**
     * Connect to WebSocket server
     */
    connect(): Promise<void> {
        return new Promise((resolve, reject) => {
            try {
                this.ws = new WebSocket(this.url);

                this.ws.onopen = () => {
                    logger.info('WebSocket connected');
                    this.reconnectAttempts = 0;
                    this.flushMessageQueue();

                    if (this.onConnect) {
                        this.onConnect();
                    }

                    resolve();
                };

                this.ws.onmessage = (event) => {
                    try {
                        const message = JSON.parse(event.data) as SignalWebSocketMessage;
                        logger.debug(`Received message from ${message.from}`);
                        this.onMessage(message);
                    } catch (error) {
                        logger.error('Failed to parse WebSocket message:', error);
                    }
                };

                this.ws.onerror = (error) => {
                    logger.error('WebSocket error:', error);
                    reject(error);
                };

                this.ws.onclose = () => {
                    logger.warn('WebSocket disconnected');

                    if (this.onDisconnect) {
                        this.onDisconnect();
                    }

                    this.attemptReconnect();
                };
            } catch (error) {
                logger.error('Failed to create WebSocket:', error);
                reject(error);
            }
        });
    }

    /**
     * Send a message through WebSocket
     */
    send(message: SignalWebSocketMessage): void {
        const messageStr = JSON.stringify(message);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(messageStr);
            logger.debug(`Sent message to ${message.to}`);
        } else {
            logger.warn('WebSocket not connected, queueing message');
            this.messageQueue.push(message);
        }
    }

    /**
     * Send an encrypted message
     */
    sendEncrypted(
        to: string,
        encrypted: CiphertextMessage,
        deviceId: number = 1
    ): void {
        const message: SignalWebSocketMessage = {
            type: 'message',
            from: 'self', // Should be replaced with actual user ID
            to,
            deviceId,
            timestamp: Date.now(),
            data: {
                type: encrypted.type,
                body: btoa(String.fromCharCode(...encrypted.body)),
                registrationId: encrypted.registrationId,
                preKeyId: encrypted.preKeyId,
                signedPreKeyId: encrypted.signedPreKeyId,
                baseKey: encrypted.baseKey ? btoa(String.fromCharCode(...encrypted.baseKey)) : undefined,
                identityKey: encrypted.identityKey ? btoa(String.fromCharCode(...encrypted.identityKey)) : undefined
            }
        };

        this.send(message);
    }

    /**
     * Send a typing indicator
     */
    sendTypingIndicator(to: string, isTyping: boolean): void {
        const message: SignalWebSocketMessage = {
            type: 'typing',
            from: 'self',
            to,
            deviceId: 1,
            timestamp: Date.now(),
            data: { isTyping }
        };

        this.send(message);
    }

    /**
     * Send a read receipt
     */
    sendReadReceipt(to: string, messageIds: string[]): void {
        const message: SignalWebSocketMessage = {
            type: 'receipt',
            from: 'self',
            to,
            deviceId: 1,
            timestamp: Date.now(),
            data: { messageIds, type: 'read' }
        };

        this.send(message);
    }

    /**
     * Disconnect from WebSocket
     */
    disconnect(): void {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    /**
     * Attempt to reconnect
     */
    private attemptReconnect(): void {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            logger.error('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

        logger.info(`Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);

        setTimeout(() => {
            this.connect().catch((error) => {
                logger.error('Reconnection failed:', error);
            });
        }, delay);
    }

    /**
     * Flush queued messages
     */
    private flushMessageQueue(): void {
        while (this.messageQueue.length > 0) {
            const message = this.messageQueue.shift();
            if (message) {
                this.send(message);
            }
        }
    }
}
