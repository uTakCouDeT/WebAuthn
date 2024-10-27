import React from 'react';
import './App.css';
import RegistrationForm from './RegistrationForm';
import LoginForm from './LoginForm';

function App() {
    return (
        <div className="App">
            <header className="App-header">
                <h1>WebAuthn Demo</h1>
                <RegistrationForm />
                <LoginForm />
            </header>
        </div>
    );
}

export default App;
