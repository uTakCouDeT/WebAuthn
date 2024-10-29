// frontend/src/RegistrationForm.js
import React, { useState } from 'react';
import axios from 'axios';

// Функция для преобразования строки base64url в Uint8Array
function base64urlToUint8Array(base64urlString) {
    if (!base64urlString || typeof base64urlString !== 'string') {
        console.error('Invalid base64urlString:', base64urlString);
        return new Uint8Array(); // возвращаем пустой массив, если строка недействительна
    }

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

// Функция для преобразования ArrayBuffer в base64url строку
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
            // Запрос для начала регистрации
            const response = await axios.get('/auth/start-registration/', {
                withCredentials: true
            });

            if (typeof response.data !== 'object' || !response.data.publicKey || !response.data.publicKey.challenge) {
                throw new Error('Unexpected response format');
            }

            const options = response.data.publicKey;

            console.log('Registration options:', options);

            // Преобразование challenge и user.id в формат Uint8Array
            options.challenge = base64urlToUint8Array(options.challenge);
            options.user.id = base64urlToUint8Array(options.user.id);

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

            // Отправка данных на сервер для завершения регистрации
            await axios.post('/auth/finish-registration/', attestationResponse, {
                withCredentials: true,
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            setStatus('Регистрация завершена успешно');
        } catch (error) {
            console.error('Error during registration:', error);
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
