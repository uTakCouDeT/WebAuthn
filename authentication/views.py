# authentication/views.py

import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from .models import UserKey
from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    AttestationObject,
    AuthenticatorData,
    CollectedClientData,
    UserVerificationRequirement,
)
from cbor2 import loads as cbor2_loads
from base64 import urlsafe_b64encode

def serialize_credential_creation_options(options):
    # Преобразуем challenge и user.id в формат Base64 URL
    challenge_base64 = urlsafe_b64encode(options.public_key.challenge).rstrip(b'=').decode('utf-8')
    user_id_base64 = urlsafe_b64encode(options.public_key.user.id).rstrip(b'=').decode('utf-8')

    # Создаем новый словарь с сериализованными данными
    registration_data = {
        'publicKey': {
            'rp': {
                'name': options.public_key.rp.name,
                'id': options.public_key.rp.id,
            },
            'user': {
                'name': options.public_key.user.name,
                'id': user_id_base64,
                'displayName': options.public_key.user.display_name,
            },
            'challenge': challenge_base64,
            'pubKeyCredParams': [
                {'type': param.type.value, 'alg': param.alg} for param in options.public_key.pub_key_cred_params
            ],
            'timeout': options.public_key.timeout,
            'excludeCredentials': [
                {'type': cred.type.value, 'id': urlsafe_b64encode(cred.id).rstrip(b'=').decode('utf-8')}
                for cred in options.public_key.exclude_credentials
            ],
            'authenticatorSelection': {
                'authenticatorAttachment': options.public_key.authenticator_selection.authenticator_attachment,
                'residentKey': options.public_key.authenticator_selection.resident_key.value,
                'userVerification': options.public_key.authenticator_selection.user_verification.value,
                'requireResidentKey': options.public_key.authenticator_selection.require_resident_key,
            },
            'attestation': options.public_key.attestation,
            'extensions': options.public_key.extensions,
        }
    }

    return registration_data


# Настройки RP (Relying Party)
RP_ID = 'localhost'
RP_NAME = 'WebAuthn Demo'
ORIGIN = 'https://localhost:3000'  # Замените на ваш фронтенд URL

# Инициализация FIDO2 сервера
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)


@csrf_exempt
def start_registration(request):
    if request.method == 'GET':
        # Получаем или создаем пользователя
        user, created = User.objects.get_or_create(username="demo_user", defaults={"password": "testpassword"})
        user_id = str(user.id).encode('utf-8')

        # Создаем список исключаемых credential_ids (если пользователь уже имеет зарегистрированные ключи)
        exclude_credentials = []
        user_keys = UserKey.objects.filter(user=user)
        for key in user_keys:
            exclude_credentials.append(
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=websafe_decode(key.credential_id),
                )
            )

        # Создаем объект пользователя для регистрации
        user_entity = PublicKeyCredentialUserEntity(
            id=user_id,
            name=user.username,
            display_name="Demo User",
        )

        # Генерируем challenge и параметры для регистрации
        credential_creation_options, state = server.register_begin(
            user=user_entity,
            credentials=exclude_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        # Сохраняем состояние в сессии
        request.session['fido2_state'] = state

        # Возвращаем данные клиенту
        registration_data = serialize_credential_creation_options(credential_creation_options)
        print("-----------------------------------------------------------------------------")
        print(registration_data)
        print("-----------------------------------------------------------------------------")
        return JsonResponse(registration_data, safe=False)

    else:
        return JsonResponse({'error': 'GET method required'}, status=405)


@csrf_exempt
def finish_registration(request):
    if request.method == 'POST':
        data = cbor2_loads(request.body)

        # Получаем состояние из сессии
        state = request.session.get('fido2_state')
        if not state:
            return JsonResponse({"error": "No registration state found in session"}, status=400)

        try:
            # Завершаем регистрацию
            auth_data = server.register_complete(
                state,
                data,
            )

            # Получаем пользователя
            user_id = state['user'].id
            user = User.objects.get(id=int(user_id.decode('utf-8')))

            # Сохраняем информацию о ключе пользователя
            UserKey.objects.create(
                user=user,
                credential_id=websafe_encode(auth_data.credential_id).decode('utf-8'),
                public_key=auth_data.credential_public_key.decode('utf-8'),
                sign_count=auth_data.sign_count,
            )

            # Удаляем состояние из сессии
            del request.session['fido2_state']

            return JsonResponse({"status": "Registration completed successfully"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({'error': 'POST method required'}, status=405)


@csrf_exempt
def start_authentication(request):
    if request.method == 'GET':
        # Получаем пользователя
        user = User.objects.get(username="demo_user")

        # Получаем зарегистрированные ключи пользователя
        user_keys = UserKey.objects.filter(user=user)
        if not user_keys:
            return JsonResponse({'error': 'No registered keys for user'}, status=404)

        # Формируем список зарегистрированных credential_ids
        allowed_credentials = []
        for key in user_keys:
            allowed_credentials.append(
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=websafe_decode(key.credential_id),
                )
            )

        # Генерируем challenge и параметры для аутентификации
        auth_data, state = server.authenticate_begin(
            credentials=allowed_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        # Сохраняем состояние в сессии
        request.session['fido2_state'] = state

        # Возвращаем данные клиенту
        print("-----------------------------------------------------------------------------")
        print(auth_data)
        print("-----------------------------------------------------------------------------")
        return JsonResponse(auth_data, safe=False)
    else:
        return JsonResponse({'error': 'GET method required'}, status=405)


@csrf_exempt
def finish_authentication(request):
    if request.method == 'POST':
        data = cbor2_loads(request.body)

        # Получаем состояние из сессии
        state = request.session.get('fido2_state')
        if not state:
            return JsonResponse({"error": "No authentication state found in session"}, status=400)

        # Собираем информацию о зарегистрированных ключах
        user_keys = UserKey.objects.all()
        credentials = {}
        for key in user_keys:
            cred_id = websafe_decode(key.credential_id)
            credentials[cred_id] = {
                'public_key': key.public_key.encode('utf-8'),
                'sign_count': key.sign_count,
                'user_handle': str(key.user.id).encode('utf-8'),
            }

        try:
            # Завершаем аутентификацию
            auth_data = server.authenticate_complete(
                state,
                credentials,
                data,
            )

            # Обновляем счетчик sign_count
            credential_id_encoded = websafe_encode(auth_data.credential_id).decode('utf-8')
            user_key = UserKey.objects.get(credential_id=credential_id_encoded)
            user_key.sign_count = auth_data.new_sign_count
            user_key.save()

            # Удаляем состояние из сессии
            del request.session['fido2_state']

            return JsonResponse({"status": "Authentication successful"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({'error': 'POST method required'}, status=405)
