// frontend/src/LoginForm.js
import React, { useState } from 'react';
import axios from 'axios';

function base64urlToUint8Array(base64urlString) {
    const padding = '='.repeat((4 - (base64urlString.length % 4)) % 4);
    const base64 = (base64urlString + padding)
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

function arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    const base64String = window.btoa(binary);
    return base64String
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

const LoginForm = () => {
    const [status, setStatus] = useState('');

    const startAuthentication = async () => {
        try {
            // Шаг 1: Инициализация аутентификации
            const response = await axios.get('https://localhost:8000/auth/start-authentication/', {
                withCredentials: true
            });

            const options = response.data;

            // Преобразуем challenge в Uint8Array
            options.challenge = base64urlToUint8Array(options.challenge);

            // Преобразуем allowCredentials, если есть
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => {
                    return {
                        ...cred,
                        id: base64urlToUint8Array(cred.id)
                    };
                });
            }

            // Шаг 2: Вызов WebAuthn API для аутентификации
            const assertion = await navigator.credentials.get({
                publicKey: options
            });

            // Шаг 3: Подготовка данных для отправки на сервер
            const authenticationResponse = {
                id: assertion.id,
                rawId: arrayBufferToBase64url(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
                    authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
                    signature: arrayBufferToBase64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null,
                },
                clientExtensionResults: assertion.getClientExtensionResults(),
            };

            // Шаг 4: Отправка данных на сервер
            await axios.post('https://localhost:8000/auth/finish-authentication/', authenticationResponse, {
                withCredentials: true,
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            setStatus('Аутентификация успешно завершена');
        } catch (error) {
            console.error(error);
            setStatus('Ошибка при аутентификации: ' + error.message);
        }
    };

    return (
        <div>
            <h2>Вход с помощью WebAuthn</h2>
            <button onClick={startAuthentication}>Войти</button>
            <p>{status}</p>
        </div>
    );
};

export default LoginForm;
