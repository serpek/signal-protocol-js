
import { LibSignalAdapter } from './libsignal-adapter';
import { OurLibraryAdapter } from './our-library-adapter';

// Color codes for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
};

function log(message: string, color: string = colors.reset) {
    console.log(`${color}${message}${colors.reset}`);
}

function logSection(title: string) {
    console.log('\n' + '='.repeat(60));
    log(title, colors.bright + colors.cyan);
    console.log('='.repeat(60));
}

function logSuccess(message: string) {
    log(`✓ ${message}`, colors.green);
}

function logError(message: string) {
    log(`✗ ${message}`, colors.red);
}

function logInfo(message: string) {
    log(`→ ${message}`, colors.blue);
}

/**
 * Run compatibility tests between LibSignal and our implementation
 */
async function runCompatibilityTest() {
    logSection('SIGNAL PROTOCOL COMPATIBILITY TEST');
    log('Testing compatibility between @signalapp/libsignal-client and our implementation\n');

    try {
        // Initialize both libraries
        logInfo('Initializing libraries...');
        const alice = new LibSignalAdapter(); // Using official libsignal
        const bob = new OurLibraryAdapter();  // Using our implementation
        await bob.initialize();
        logSuccess('Both libraries initialized');

        // ============================================
        // TEST 1: LibSignal → Our Library
        // ============================================
        logSection('TEST 1: LibSignal (Alice) → Our Library (Bob)');

        // Generate Bob's prekey bundle using our library
        logInfo('Generating Bob\'s prekey bundle (our library)...');
        const bobBundle = await bob.generatePreKeyBundle();
        logSuccess(`Bob's bundle generated with registration ID: ${bobBundle.registrationId}`);
console.log(bobBundle)
        // Alice processes Bob's bundle using libsignal
        logInfo('Alice processing Bob\'s bundle (libsignal)...');
        await alice.processPreKeyBundle('bob', bobBundle);
        logSuccess('Alice established session with Bob');

        // Alice encrypts message using libsignal
        const message1 = 'Hello Bob! This is Alice using libsignal.';
        logInfo(`Alice encrypting: "${message1}"`);
        const encrypted1 = await alice.encrypt('bob', 1, message1);
        logSuccess(`Message encrypted (type: ${encrypted1.type}, size: ${encrypted1.body.length} bytes)`);

        // Bob decrypts using our library
        logInfo('Bob decrypting message...');
        const decrypted1 = await bob.decrypt('alice', {
            type: encrypted1.type,
            body: encrypted1.body,
            registrationId: encrypted1.registrationId
        });
        logSuccess(`Bob decrypted: "${decrypted1}"`);

        // Verify message integrity
        if (decrypted1 === message1) {
            logSuccess('✓ Message integrity verified - EXACT MATCH!');
        } else {
            logError(`✗ Message mismatch!\nExpected: "${message1}"\nReceived: "${decrypted1}"`);
            throw new Error('Message integrity check failed');
        }

        // ============================================
        // TEST 2: Our Library → LibSignal
        // ============================================
        logSection('TEST 2: Our Library (Bob) → LibSignal (Alice)');

        // Generate Alice's prekey bundle using libsignal
        logInfo('Generating Alice\'s prekey bundle (libsignal)...');
        const aliceBundle = await alice.generatePreKeyBundle();
        logSuccess(`Alice's bundle generated with registration ID: ${aliceBundle.registrationId}`);

        // Bob processes Alice's bundle using our library
        logInfo('Bob processing Alice\'s bundle (our library)...');
        await bob.processPreKeyBundle('alice', aliceBundle);
        logSuccess('Bob established session with Alice');

        // Bob encrypts message using our library
        const message2 = 'Hello Alice! This is Bob using our custom implementation.';
        logInfo(`Bob encrypting: "${message2}"`);
        const encrypted2 = await bob.encrypt('alice', message2);
        logSuccess(`Message encrypted (type: ${encrypted2.type}, size: ${encrypted2.body.length} bytes)`);

        // Alice decrypts using libsignal
        logInfo('Alice decrypting message...');
        const decrypted2 = await alice.decrypt('bob', 1, {
            type: encrypted2.type,
            body: encrypted2.body
        });
        logSuccess(`Alice decrypted: "${decrypted2}"`);

        // Verify message integrity
        if (decrypted2 === message2) {
            logSuccess('✓ Message integrity verified - EXACT MATCH!');
        } else {
            logError(`✗ Message mismatch!\nExpected: "${message2}"\nReceived: "${decrypted2}"`);
            throw new Error('Message integrity check failed');
        }

        // ============================================
        // TEST 3: Bidirectional Communication
        // ============================================
        logSection('TEST 3: Bidirectional Communication');

        const messages = [
            { from: 'alice', to: 'bob', text: 'How are you doing?' },
            { from: 'bob', to: 'alice', text: 'I am doing great, thanks!' },
            { from: 'alice', to: 'bob', text: 'That sounds wonderful!' },
            { from: 'bob', to: 'alice', text: 'Yes, everything is working perfectly.' },
            { from: 'alice', to: 'bob', text: '🚀 Encryption is awesome!' },
        ];

        for (const msg of messages) {
            logInfo(`${msg.from} → ${msg.to}: "${msg.text}"`);

            if (msg.from === 'alice') {
                // Alice sends to Bob
                const encrypted = await alice.encrypt('bob', 1, msg.text);
                const decrypted = await bob.decrypt('alice', {
                    type: encrypted.type,
                    body: encrypted.body,
                    registrationId: encrypted.registrationId
                });

                if (decrypted === msg.text) {
                    logSuccess(`Message verified: "${decrypted}"`);
                } else {
                    logError(`Message mismatch!`);
                    throw new Error('Bidirectional test failed');
                }
            } else {
                // Bob sends to Alice
                const encrypted = await bob.encrypt('alice', msg.text);
                const decrypted = await alice.decrypt('bob', 1, {
                    type: encrypted.type,
                    body: encrypted.body
                });

                if (decrypted === msg.text) {
                    logSuccess(`Message verified: "${decrypted}"`);
                } else {
                    logError(`Message mismatch!`);
                    throw new Error('Bidirectional test failed');
                }
            }
        }

        // ============================================
        // TEST 4: Large Message Test
        // ============================================
        logSection('TEST 4: Large Message Test');

        const largeMessage = 'Lorem ipsum '.repeat(100) + '🔐';
        logInfo(`Testing with large message (${largeMessage.length} chars)...`);

        // Alice sends large message to Bob
        const encryptedLarge = await alice.encrypt('bob', 1, largeMessage);
        logSuccess(`Encrypted large message (${encryptedLarge.body.length} bytes)`);

        const decryptedLarge = await bob.decrypt('alice', {
            type: encryptedLarge.type,
            body: encryptedLarge.body,
            registrationId: encryptedLarge.registrationId
        });

        if (decryptedLarge === largeMessage) {
            logSuccess('✓ Large message integrity verified!');
        } else {
            logError('✗ Large message test failed!');
            throw new Error('Large message test failed');
        }

        // ============================================
        // TEST SUMMARY
        // ============================================
        logSection('TEST SUMMARY');
        logSuccess('✓ All compatibility tests passed!');
        logSuccess('✓ LibSignal → Our Library: SUCCESS');
        logSuccess('✓ Our Library → LibSignal: SUCCESS');
        logSuccess('✓ Bidirectional Communication: SUCCESS');
        logSuccess('✓ Large Message Test: SUCCESS');
        log('\n🎉 Full compatibility confirmed! Our implementation is 100% compatible with Signal Protocol!', colors.bright + colors.green);

    } catch (error) {
        logSection('TEST FAILED');
        logError(`Error: ${error}`);
        console.error(error);
        process.exit(1);
    }
}

// Setup environment and run test
async function main() {
    // Setup crypto for Node.js
    if (typeof globalThis.crypto === 'undefined') {
        const { webcrypto } = await import('crypto');
        (globalThis as any).crypto = webcrypto;
    }

    // Setup IndexedDB for Node.js
    // IMPORTANT: Import fake-indexeddb before any code that uses IndexedDB
    await import('fake-indexeddb/auto');

    // Now run the compatibility test
    await runCompatibilityTest();
}

// Run the test
main().catch(console.error);
