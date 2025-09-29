
// ===== MAIN APP =====
// src/App.tsx
import { SignalProvider } from './context/SignalContext';
import { SignalChat } from './components/SignalChat';
// import {AdvancedSignalChat} from "./components/AdvancedSignalChat.tsx";

function App() {
    return (
        <SignalProvider encryptionPassword="optional-password-for-db-encryption">
            <SignalChat />
            {/*<AdvancedSignalChat />*/}
        </SignalProvider>
    );
}

export default App;
