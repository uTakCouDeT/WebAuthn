import json
import base64
import uuid
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from .models import WebAuthnDevice
from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response
)
from webauthn.helpers import (
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)


@csrf_exempt
@api_view(['POST'])
def register_device(request):
    data = request.data
    user_login = data.get("user_login")  # Получаем `user_login` от клиента

    # Создаем параметры для регистрации
    registration_options = generate_registration_options(
        rp_id="localhost",
        rp_name="Your Site Name",
        user_id=bytes(user_login, 'utf-8'),  # Используем `user_login` как `user_id`
        user_name=user_login,
        user_display_name="User",
        attestation=AttestationConveyancePreference.DIRECT
    )

    # Сохраняем challenge в сессии
    request.session['registration_challenge'] = base64.urlsafe_b64encode(registration_options.challenge).decode()

    # Отправляем challenge и параметры пользователя на фронтенд
    response_data = {
        "challenge": list(registration_options.challenge),
        "rp": {
            "id": registration_options.rp.id,
            "name": registration_options.rp.name
        },
        "user": {
            "id": list(registration_options.user.id),
            "name": registration_options.user.name,
            "displayName": registration_options.user.display_name
        },
        "pubKeyCredParams": [param.__dict__ for param in registration_options.pub_key_cred_params],
    }

    return JsonResponse(response_data)


@csrf_exempt
@api_view(['POST'])
def complete_registration(request):
    data = request.data
    user_login = data.get("user_login")  # Получаем `user_login`

    # Декодируем сохраненный challenge
    challenge = base64url_to_bytes(request.session.get('registration_challenge'))

    # Создаем объект credential
    credential = {
        "id": data['id'],
        "rawId": data['id'],
        "response": {
            "attestationObject": data['response']['attestationObject'],
            "clientDataJSON": data['response']['clientDataJSON']
        },
        "type": data.get("type"),
    }

    try:
        # Верификация ответа регистрацией
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id="localhost",
            expected_origin="http://localhost:8000",
            require_user_verification=True
        )

        # Сохранение устройства в базе данных
        WebAuthnDevice.objects.create(
            user=request.user if request.user.is_authenticated else None,
            user_login=user_login,
            credential_id=data['id'],
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            device_name=data.get("device_name", "Unknown Device")
        )

        return JsonResponse({"status": "registered"})
    except Exception as e:
        print("Registration error:", str(e))
        return JsonResponse({"status": "error", "message": str(e)})


@csrf_exempt
@api_view(['POST'])
def authenticate_device(request):
    data = request.data
    user_login = data.get("user_login")  # Получаем `user_login`

    # Генерация опций для аутентификации
    authentication_options = generate_authentication_options(
        rp_id="localhost",
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=device.credential_id, type="public-key")
            for device in WebAuthnDevice.objects.filter(user_login=user_login)
        ],
        user_verification=UserVerificationRequirement.PREFERRED
    )

    # Сохраняем challenge для последующей проверки
    request.session['authentication_challenge'] = base64.urlsafe_b64encode(authentication_options.challenge).decode()

    return JsonResponse({
        "challenge": list(authentication_options.challenge),
        "allowCredentials": [
            {
                "id": base64.urlsafe_b64encode(desc.id.encode('utf-8')).decode('utf-8'),
                "type": desc.type
            } for desc in authentication_options.allow_credentials
        ]
    })


@csrf_exempt
@api_view(['POST'])
def complete_authentication(request):
    data = request.data
    user_login = data.get("user_login")  # Получаем `user_login`

    # Преобразование значений из JSON
    credential_id = base64url_to_bytes(data['credential_id'])
    authenticator_data = base64url_to_bytes(data['authenticator_data'])
    client_data_json = base64url_to_bytes(data['client_data_json'])
    signature = base64url_to_bytes(data['signature'])

    # Декодируем challenge из сессии
    challenge = base64url_to_bytes(request.session.get('authentication_challenge'))

    try:
        device = WebAuthnDevice.objects.get(credential_id=credential_id, user_login=user_login)

        # Верификация аутентификации
        verify_authentication_response(
            credential=data,
            expected_challenge=challenge,
            expected_rp_id="localhost",
            expected_origin="https://localhost",
            credential_public_key=device.public_key,
            credential_current_sign_count=device.sign_count,
            require_user_verification=True
        )

        # Обновление счетчика и сохранение
        device.sign_count += 1
        device.save()
        return JsonResponse({"status": "authenticated"})
    except Exception as e:
        print("Authentication error:", str(e))
        return JsonResponse({"status": "error", "message": str(e)})
