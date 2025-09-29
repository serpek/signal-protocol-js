// ===== EXAMPLE REACT COMPONENT =====
// src/components/SignalChat.tsx
import { useState, useEffect } from 'react';
import { useSignalMessaging } from '../hooks/useSignalMessaging';
import { useSignal } from '../context/SignalContext';

export function SignalChat() {
    const signal = useSignal();
    const messaging = useSignalMessaging();
    const [recipientId, setRecipientId] = useState('');
    const [message, setMessage] = useState('');
    const [preKeyBundle, setPreKeyBundle] = useState('');
    const [myPreKeyBundle, setMyPreKeyBundle] = useState<string | null>(null);

    useEffect(() => {
        if (signal.isInitialized) {
            // Generate and display our prekey bundle
            signal.getPreKeyBundle().then(bundle => {
                setMyPreKeyBundle(btoa(JSON.stringify(bundle)));
            });
        }
    }, [signal.isInitialized]);

    const handleEstablishSession = async () => {
        try {
            const bundle = JSON.parse(atob(preKeyBundle));

            // Convert base64 strings back to Uint8Arrays
            bundle.identityKey = Uint8Array.from(atob(bundle.identityKey), c => c.charCodeAt(0));
            bundle.signedPreKeyPublic = Uint8Array.from(atob(bundle.signedPreKeyPublic), c => c.charCodeAt(0));
            bundle.signedPreKeySignature = Uint8Array.from(atob(bundle.signedPreKeySignature), c => c.charCodeAt(0));

            if (bundle.preKeyPublic) {
                bundle.preKeyPublic = Uint8Array.from(atob(bundle.preKeyPublic), c => c.charCodeAt(0));
            }

            await messaging.establishSession(recipientId, bundle);
            alert('Session established!');
        } catch (error) {
            console.error('Failed to establish session:', error);
            alert('Failed to establish session');
        }
    };

    const handleSendMessage = async () => {
        try {
            await messaging.sendMessage(recipientId, message);
            setMessage('');
        } catch (error) {
            console.error('Failed to send message:', error);
            alert('Failed to send message. Make sure session is established.');
        }
    };

    if (!signal.isInitialized) {
        return <div>Initializing Signal Protocol...</div>;
    }

    return (
        <div style={{ padding: '20px', fontFamily: 'monospace' }}>
            <h2>Signal Protocol Demo</h2>

            <div style={{ marginBottom: '20px', padding: '10px', background: '#f0f0f0' }}>
                <h3>My PreKey Bundle (share this with others):</h3>
                <textarea
                    value={myPreKeyBundle || 'Generating...'}
                    readOnly
                    style={{ width: '100%', height: '100px', fontSize: '10px' }}
                />
            </div>

            <div style={{ marginBottom: '20px', padding: '10px', background: '#f0f0f0' }}>
                <h3>Establish Session</h3>
                <input
                    type="text"
                    placeholder="Recipient ID"
                    value={recipientId}
                    onChange={(e) => setRecipientId(e.target.value)}
                    style={{ marginRight: '10px', padding: '5px' }}
                />
                <br /><br />
                <textarea
                    placeholder="Paste recipient's PreKey Bundle here"
                    value={preKeyBundle}
                    onChange={(e) => setPreKeyBundle(e.target.value)}
                    style={{ width: '100%', height: '100px', fontSize: '10px' }}
                />
                <br /><br />
                <button onClick={handleEstablishSession}>Establish Session</button>
            </div>

            <div style={{ marginBottom: '20px', padding: '10px', background: '#f0f0f0' }}>
                <h3>Send Message</h3>
                <input
                    type="text"
                    placeholder="Message"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    style={{ marginRight: '10px', padding: '5px', width: '300px' }}
                />
                <button onClick={handleSendMessage}>Send Encrypted</button>
            </div>

            <div style={{ marginBottom: '20px', padding: '10px', background: '#f0f0f0' }}>
                <h3>Messages</h3>
                {messaging.messages.map((msg) => (
                    <div key={msg.id} style={{ marginBottom: '10px' }}>
                        <strong>{msg.senderId === 'me' ? 'Me' : msg.senderId}:</strong> {msg.content}
                        <span style={{ marginLeft: '10px', fontSize: '10px', color: '#666' }}>
        {new Date(msg.timestamp).toLocaleTimeString()}
                            {msg.encrypted && ' 🔐'}
        </span>
                    </div>
                ))}
            </div>

            <div style={{ marginBottom: '20px', padding: '10px', background: '#f0f0f0' }}>
                <h3>Active Sessions</h3>
                {messaging.sessions.length > 0 ? (
                    <ul>
                        {messaging.sessions.map((sessionId) => (
                            <li key={sessionId}>{sessionId}</li>
                        ))}
                    </ul>
                ) : (
                    <p>No active sessions</p>
                )}
            </div>
        </div>
    );
}
