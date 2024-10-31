import React, { useState } from 'react';
import './AuthComponent.css';

function AuthComponent() {
    const [statusMessage, setStatusMessage] = useState('');
    const [userLogin, setUserLogin] = useState('');  // Состояние для хранения логина пользователя

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
    const csrftoken = getCookie('csrftoken');

    function toBase64Url(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    const handleRegister = async () => {
        if (!userLogin) {
            setStatusMessage("Введите логин для регистрации.");
            return;
        }

        const response = await fetch('/api/register-device/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrftoken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ user_login: userLogin })
        });

        const { challenge, rp, user, pubKeyCredParams } = await response.json();

        const publicKeyCredentialCreationOptions = {
            challenge: new Uint8Array(challenge),
            rp,
            user: {
                ...user,
                id: new Uint8Array(user.id)
            },
            pubKeyCredParams
        };

        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        });

        // Преобразование данных в base64url
        const credentialData = {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            response: {
                clientDataJSON: toBase64Url(credential.response.clientDataJSON),
                attestationObject: toBase64Url(credential.response.attestationObject)
            },
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment || null,
            user_login: userLogin  // Добавляем логин в запрос
        };

        console.log(credentialData);

        const registerResponse = await fetch('/api/complete-registration/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify(credentialData)
        });

        const registerResult = await registerResponse.json();
        if (registerResult.status === "registered") {
            setStatusMessage("Устройство успешно зарегистрировано.");
        } else {
            setStatusMessage(`Ошибка регистрации: ${registerResult.message}`);
        }
    };

    const handleLogin = async () => {
        if (!userLogin) {
            setStatusMessage("Введите логин для входа.");
            return;
        }

        try {
            const response = await fetch('/api/authenticate-device/', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': csrftoken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ user_login: userLogin })  // Отправка логина для аутентификации
            });
            const { challenge, allowCredentials } = await response.json();

            const publicKeyCredentialRequestOptions = {
                challenge: new Uint8Array(challenge),
                allowCredentials: allowCredentials.map(cred => ({
                    id: Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                    type: cred.type
                }))
            };

            const assertion = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });

            const authResponse = await fetch('/api/complete-authentication/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrftoken
                },
                body: JSON.stringify({
                    credential_id: toBase64Url(assertion.rawId),
                    authenticator_data: toBase64Url(assertion.response.authenticatorData),
                    client_data_json: toBase64Url(assertion.response.clientDataJSON),
                    signature: toBase64Url(assertion.response.signature),
                    user_login: userLogin
                })
            });

            const authResult = await authResponse.json();
            if (authResult.status === "authenticated") {
                setStatusMessage("Аутентификация успешна.");
            } else {
                setStatusMessage(`Ошибка аутентификации: ${authResult.message}`);
            }
        } catch (error) {
            console.error("Authentication error:", error);
            setStatusMessage("Authentication failed. Please try again.");
        }
    };

    return (
        <div className="auth-container">
            <h1>WebAuthn Аутентификация</h1>
            <input
                type="text"
                placeholder="Введите логин"
                value={userLogin}
                onChange={(e) => setUserLogin(e.target.value)}
                className="login-input"
            />
            <p className="status-message">{statusMessage}</p>
            <div className="button-group">
                <button className="auth-button" onClick={handleRegister}>Зарегистрировать устройство</button>
                <button className="auth-button" onClick={handleLogin}>Войти</button>
            </div>
        </div>
    );
}

export default AuthComponent;
