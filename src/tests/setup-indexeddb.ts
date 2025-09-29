
// ===== SETUP SCRIPT FOR INDEXEDDB =====
// src/tests/setup-indexeddb.ts
// This file ensures IndexedDB is available in Node.js environment

export async function setupIndexedDB() {
    if (typeof window === 'undefined') {
        // We're in Node.js
        const { default: FDBFactory } = await import('fake-indexeddb/lib/FDBFactory');
        const { default: FDBKeyRange } = await import('fake-indexeddb/lib/FDBKeyRange');

        (globalThis as any).indexedDB = new FDBFactory();
        (globalThis as any).IDBKeyRange = FDBKeyRange;

        // Also setup other IDB globals
        (globalThis as any).IDBCursor = (await import('fake-indexeddb/lib/FDBCursor')).default;
        (globalThis as any).IDBDatabase = (await import('fake-indexeddb/lib/FDBDatabase')).default;
        (globalThis as any).IDBIndex = (await import('fake-indexeddb/lib/FDBIndex')).default;
        (globalThis as any).IDBObjectStore = (await import('fake-indexeddb/lib/FDBObjectStore')).default;
        (globalThis as any).IDBRequest = (await import('fake-indexeddb/lib/FDBRequest')).default;
        (globalThis as any).IDBTransaction = (await import('fake-indexeddb/lib/FDBTransaction')).default;
        (globalThis as any).IDBVersionChangeEvent = (await import('fake-indexeddb/lib/FDBVersionChangeEvent')).default;
    }
}
