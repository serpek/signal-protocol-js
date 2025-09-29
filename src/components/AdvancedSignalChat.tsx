
// ===== ADVANCED REACT COMPONENTS =====
// src/components/AdvancedSignalChat.tsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { useSignal } from '../context/SignalContext';
import { useSignalMessaging } from '../hooks/useSignalMessaging';
import { WebSocketTransport, SignalWebSocketMessage } from '../transport/websocket-transport';
import { CiphertextMessage } from '../session/session-cipher';

interface Contact {
    id: string;
    name: string;
    hasSession: boolean;
    isTyping: boolean;
    lastSeen?: number;
}

export function AdvancedSignalChat() {
    const signal = useSignal();
    const messaging = useSignalMessaging();
    const [contacts, setContacts] = useState<Contact[]>([]);
    const [selectedContact, setSelectedContact] = useState<string | null>(null);
    const [message, setMessage] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('disconnected');
    const transportRef = useRef<WebSocketTransport | null>(null);
    const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);

    // Initialize WebSocket transport
    useEffect(() => {
        if (signal.isInitialized) {
            const transport = new WebSocketTransport(
                'wss://your-signal-server.com/ws',
                handleIncomingMessage,
                () => setConnectionStatus('connected'),
                () => setConnectionStatus('disconnected')
            );

            transport.connect()
                .then(() => {
                    transportRef.current = transport;
                    setConnectionStatus('connected');
                })
                .catch((error) => {
                    console.error('Failed to connect:', error);
                    setConnectionStatus('disconnected');
                });

            return () => {
                transport.disconnect();
            };
        }
    }, [signal.isInitialized]);

    // Handle incoming WebSocket messages
    const handleIncomingMessage = useCallback(async (wsMessage: SignalWebSocketMessage) => {
        switch (wsMessage.type) {
            case 'message':
                // Convert back from base64
                const encrypted: CiphertextMessage = {
                    type: wsMessage.data.type,
                    body: Uint8Array.from(atob(wsMessage.data.body), c => c.charCodeAt(0)),
                    registrationId: wsMessage.data.registrationId,
                    preKeyId: wsMessage.data.preKeyId,
                    signedPreKeyId: wsMessage.data.signedPreKeyId,
                    baseKey: wsMessage.data.baseKey ?
                        Uint8Array.from(atob(wsMessage.data.baseKey), c => c.charCodeAt(0)) : undefined,
                    identityKey: wsMessage.data.identityKey ?
                        Uint8Array.from(atob(wsMessage.data.identityKey), c => c.charCodeAt(0)) : undefined
                };

                await messaging.receiveMessage(wsMessage.from, encrypted);
                break;

            case 'typing':
                setContacts(prev => prev.map(c =>
                    c.id === wsMessage.from ? { ...c, isTyping: wsMessage.data.isTyping } : c
                ));
                break;

            case 'receipt':
                // Handle read receipts
                console.log(`${wsMessage.from} read messages:`, wsMessage.data.messageIds);
                break;

            case 'prekey_bundle':
                // Handle incoming prekey bundle for session establishment
                await messaging.establishSession(wsMessage.from, wsMessage.data);
                break;
        }
    }, [messaging]);

    // Handle message sending
    const handleSendMessage = async () => {
        if (!selectedContact || !message.trim()) return;

        try {
            const encrypted = await messaging.sendMessage(selectedContact, message);

            if (transportRef.current) {
                transportRef.current.sendEncrypted(selectedContact, encrypted);
            }

            setMessage('');
            stopTyping();
        } catch (error) {
            console.error('Failed to send message:', error);
        }
    };

    // Handle typing indicator
    const handleTyping = () => {
        if (!selectedContact || !transportRef.current) return;

        if (!isTyping) {
            setIsTyping(true);
            transportRef.current.sendTypingIndicator(selectedContact, true);
        }

        // Reset typing timeout
        if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
        }

        typingTimeoutRef.current = setTimeout(stopTyping, 3000);
    };

    const stopTyping = () => {
        if (isTyping && selectedContact && transportRef.current) {
            setIsTyping(false);
            transportRef.current.sendTypingIndicator(selectedContact, false);
        }

        if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
            typingTimeoutRef.current = null;
        }
    };

    // Add new contact
    const handleAddContact = () => {
        const contactId = prompt('Enter contact ID:');
        if (contactId) {
            const newContact: Contact = {
                id: contactId,
                name: contactId,
                hasSession: messaging.hasSession(contactId),
                isTyping: false
            };

            setContacts(prev => [...prev, newContact]);
        }
    };

    // Establish session with contact
    const handleEstablishSession = async (contactId: string) => {
        const bundleStr = prompt("Paste contact's PreKey Bundle:");
        if (!bundleStr) return;

        try {
            const bundle = JSON.parse(atob(bundleStr));

            // Convert base64 strings to Uint8Arrays
            bundle.identityKey = Uint8Array.from(atob(bundle.identityKey), c => c.charCodeAt(0));
            bundle.signedPreKeyPublic = Uint8Array.from(atob(bundle.signedPreKeyPublic), c => c.charCodeAt(0));
            bundle.signedPreKeySignature = Uint8Array.from(atob(bundle.signedPreKeySignature), c => c.charCodeAt(0));

            if (bundle.preKeyPublic) {
                bundle.preKeyPublic = Uint8Array.from(atob(bundle.preKeyPublic), c => c.charCodeAt(0));
            }

            await messaging.establishSession(contactId, bundle);

            setContacts(prev => prev.map(c =>
                c.id === contactId ? { ...c, hasSession: true } : c
            ));

            alert('Session established!');
        } catch (error) {
            console.error('Failed to establish session:', error);
            alert('Failed to establish session');
        }
    };

    // Filter messages for selected contact
    const contactMessages = selectedContact ?
        messaging.messages.filter(m =>
            m.senderId === selectedContact || m.recipientId === selectedContact
        ) : [];

    return (
        <div style={{ display: 'flex', height: '100vh', fontFamily: 'system-ui' }}>
            {/* Contacts Sidebar */}
            <div style={{
                width: '300px',
                borderRight: '1px solid #ddd',
                display: 'flex',
                flexDirection: 'column'
            }}>
                {/* Connection Status */}
                <div style={{
                    padding: '10px',
                    borderBottom: '1px solid #ddd',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px'
                }}>
                    <div style={{
                        width: '10px',
                        height: '10px',
                        borderRadius: '50%',
                        backgroundColor: connectionStatus === 'connected' ? 'green' :
                            connectionStatus === 'connecting' ? 'orange' : 'red'
                    }} />
                    <span>{connectionStatus}</span>
                </div>

                {/* Contacts List */}
                <div style={{ flex: 1, overflow: 'auto' }}>
                    {contacts.map(contact => (
                        <div
                            key={contact.id}
                            onClick={() => setSelectedContact(contact.id)}
                            style={{
                                padding: '15px',
                                borderBottom: '1px solid #eee',
                                cursor: 'pointer',
                                backgroundColor: selectedContact === contact.id ? '#e3f2fd' : 'white',
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center'
                            }}
                        >
                            <div>
                                <div style={{ fontWeight: 'bold' }}>{contact.name}</div>
                                {contact.isTyping && (
                                    <div style={{ fontSize: '12px', color: '#666', fontStyle: 'italic' }}>
                                        typing...
                                    </div>
                                )}
                            </div>
                            <div style={{ display: 'flex', gap: '5px', alignItems: 'center' }}>
                                {contact.hasSession ? (
                                    <span title="Session established">🔐</span>
                                ) : (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            handleEstablishSession(contact.id);
                                        }}
                                        style={{
                                            fontSize: '12px',
                                            padding: '2px 6px',
                                            cursor: 'pointer'
                                        }}
                                    >
                                        Connect
                                    </button>
                                )}
                            </div>
                        </div>
                    ))}
                </div>

                {/* Add Contact Button */}
                <div style={{ padding: '10px', borderTop: '1px solid #ddd' }}>
                    <button
                        onClick={handleAddContact}
                        style={{
                            width: '100%',
                            padding: '10px',
                            background: '#2196F3',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer'
                        }}
                    >
                        Add Contact
                    </button>
                </div>
            </div>

            {/* Chat Area */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                {selectedContact ? (
                    <>
                        {/* Chat Header */}
                        <div style={{
                            padding: '15px',
                            borderBottom: '1px solid #ddd',
                            fontWeight: 'bold'
                        }}>
                            {contacts.find(c => c.id === selectedContact)?.name || selectedContact}
                        </div>

                        {/* Messages */}
                        <div style={{
                            flex: 1,
                            padding: '20px',
                            overflow: 'auto',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px'
                        }}>
                            {contactMessages.map(msg => (
                                <div
                                    key={msg.id}
                                    style={{
                                        alignSelf: msg.senderId === 'me' ? 'flex-end' : 'flex-start',
                                        maxWidth: '70%',
                                        padding: '10px 15px',
                                        borderRadius: '18px',
                                        backgroundColor: msg.senderId === 'me' ? '#2196F3' : '#e0e0e0',
                                        color: msg.senderId === 'me' ? 'white' : 'black'
                                    }}
                                >
                                    <div>{msg.content}</div>
                                    <div style={{
                                        fontSize: '11px',
                                        marginTop: '5px',
                                        opacity: 0.7
                                    }}>
                                        {new Date(msg.timestamp).toLocaleTimeString()}
                                        {msg.encrypted && ' 🔐'}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Message Input */}
                        <div style={{
                            padding: '15px',
                            borderTop: '1px solid #ddd',
                            display: 'flex',
                            gap: '10px'
                        }}>
                            <input
                                type="text"
                                value={message}
                                onChange={(e) => {
                                    setMessage(e.target.value);
                                    handleTyping();
                                }}
                                onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                                placeholder="Type a message..."
                                style={{
                                    flex: 1,
                                    padding: '10px',
                                    borderRadius: '20px',
                                    border: '1px solid #ddd',
                                    outline: 'none'
                                }}
                            />
                            <button
                                onClick={handleSendMessage}
                                disabled={!message.trim()}
                                style={{
                                    padding: '10px 20px',
                                    borderRadius: '20px',
                                    border: 'none',
                                    background: message.trim() ? '#2196F3' : '#ccc',
                                    color: 'white',
                                    cursor: message.trim() ? 'pointer' : 'not-allowed'
                                }}
                            >
                                Send
                            </button>
                        </div>
                    </>
                ) : (
                    <div style={{
                        flex: 1,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#666'
                    }}>
                        Select a contact to start messaging
                    </div>
                )}
            </div>
        </div>
    );
}
