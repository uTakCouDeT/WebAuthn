// frontend/src/RegistrationForm.js
import React, { useState } from 'react';
import axios from 'axios';

// Функции для работы с Base64URL
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

const RegistrationForm = () => {
    const [status, setStatus] = useState('');

    const startRegistration = async () => {
        try {
            const response = await axios.get('https://localhost:8000/auth/start-registration/', {
                withCredentials: true
            });

            const options = response.data;

            // Преобразуем challenge и user.id в Uint8Array
            options.challenge = base64urlToUint8Array(options.challenge);
            options.user.id = base64urlToUint8Array(options.user.id);

            // Преобразуем excludeCredentials, если есть
            if (options.excludeCredentials) {
                options.excludeCredentials = options.excludeCredentials.map(cred => {
                    return {
                        ...cred,
                        id: base64urlToUint8Array(cred.id)
                    };
                });
            }

            // Вызов WebAuthn API для создания нового ключа
            const credential = await navigator.credentials.create({
                publicKey: options
            });

            // Подготовка данных для отправки на сервер
            const attestationResponse = {
                id: credential.id,
                rawId: arrayBufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
                },
                clientExtensionResults: credential.getClientExtensionResults(),
            };

            // Отправка данных на сервер
            await axios.post('https://localhost:8000/auth/finish-registration/', attestationResponse, {
                withCredentials: true,
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            setStatus('Регистрация завершена успешно');
        } catch (error) {
            console.error(error);
            setStatus('Ошибка при регистрации: ' + error.message);
        }
    };

    return (
        <div>
            <h2>Регистрация WebAuthn</h2>
            <button onClick={startRegistration}>Начать регистрацию</button>
            <p>{status}</p>
        </div>
    );
};

export default RegistrationForm;
