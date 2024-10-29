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
    UserVerificationRequirement,
)
from django.shortcuts import render
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cbor2 import loads as cbor2_loads, dumps as cbor2_dumps

# Настройки сервера
RP_ID = 'localhost'
RP_NAME = 'WebAuthn Demo'
ORIGIN = 'https://localhost:8000'

# Инициализация FIDO2 сервера
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)


def index(request):
    return render(request, 'index.html')


# Сериализация параметров для регистрации
def serialize_credential_creation_options(options):
    return {
        'publicKey': {
            'rp': {
                'name': options.public_key.rp.name,
                'id': options.public_key.rp.id,
            },
            'user': {
                'name': options.public_key.user.name,
                'id': urlsafe_b64encode(options.public_key.user.id).decode(),
                'displayName': options.public_key.user.display_name,
            },
            'challenge': urlsafe_b64encode(options.public_key.challenge).decode(),
            'pubKeyCredParams': [
                {'type': param.type.value, 'alg': param.alg} for param in options.public_key.pub_key_cred_params
            ],
            'timeout': options.public_key.timeout,
            'excludeCredentials': [
                {'type': cred.type.value, 'id': urlsafe_b64encode(cred.id).decode()}
                for cred in options.public_key.exclude_credentials
            ],
            'authenticatorSelection': {
                'authenticatorAttachment': options.public_key.authenticator_selection.authenticator_attachment,
                'residentKey': options.public_key.authenticator_selection.resident_key.value,
                'userVerification': options.public_key.authenticator_selection.user_verification.value,
            },
            'attestation': options.public_key.attestation,
        }
    }


@csrf_exempt
def start_registration(request):
    if request.method == 'GET':
        try:
            user, _ = User.objects.get_or_create(username="demo_user", defaults={"password": "testpassword"})
            user_id = str(user.id).encode('utf-8')

            exclude_credentials = [
                PublicKeyCredentialDescriptor(
                    type="public-key", id=websafe_decode(key.credential_id)
                )
                for key in UserKey.objects.filter(user=user)
            ]

            user_entity = PublicKeyCredentialUserEntity(
                id=user_id,
                name=user.username,
                display_name="Demo User",
            )

            options, state = server.register_begin(
                user=user_entity,
                credentials=exclude_credentials,
                user_verification=UserVerificationRequirement.PREFERRED,
            )

            # Сохраняем состояние регистрации в сессии
            request.session['fido2_state'] = state
            registration_data = serialize_credential_creation_options(options)

            return JsonResponse(registration_data, safe=False)  # safe=False для возможности вернуть не dict
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({'error': 'GET method required'}, status=405)


@csrf_exempt
def finish_registration(request):
    if request.method == 'POST':
        data = cbor2_loads(request.body)
        state = request.session.get('fido2_state')
        if not state:
            return JsonResponse({"error": "No registration state found in session"}, status=400)

        try:
            auth_data = server.register_complete(state, data)
            user = User.objects.get(username="demo_user")

            UserKey.objects.create(
                user=user,
                credential_id=websafe_encode(auth_data.credential_id).decode(),
                public_key=auth_data.credential_public_key.decode(),
                sign_count=auth_data.sign_count,
            )

            del request.session['fido2_state']
            return JsonResponse({"status": "Registration completed successfully"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({'error': 'POST method required'}, status=405)


@csrf_exempt
def start_authentication(request):
    if request.method == 'GET':
        user = User.objects.filter(username="demo_user").first()
        if not user:
            return JsonResponse({'error': 'User not found'}, status=404)

        user_keys = UserKey.objects.filter(user=user)
        if not user_keys:
            return JsonResponse({'error': 'No registered keys for user'}, status=404)

        allowed_credentials = [
            PublicKeyCredentialDescriptor(type="public-key", id=websafe_decode(key.credential_id))
            for key in user_keys
        ]

        options, state = server.authenticate_begin(
            credentials=allowed_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        request.session['fido2_state'] = state
        return JsonResponse({
            'publicKey': {
                'challenge': urlsafe_b64encode(options.challenge).decode(),
                'timeout': options.timeout,
                'rpId': options.rp_id,
                'allowCredentials': [
                    {
                        'type': cred.type.value,
                        'id': urlsafe_b64encode(cred.id).decode(),
                    } for cred in options.allow_credentials
                ],
                'userVerification': options.user_verification.value,
            }
        })
    return JsonResponse({'error': 'GET method required'}, status=405)


@csrf_exempt
def finish_authentication(request):
    if request.method == 'POST':
        data = cbor2_loads(request.body)
        state = request.session.get('fido2_state')
        if not state:
            return JsonResponse({"error": "No authentication state found in session"}, status=400)

        try:
            user_keys = UserKey.objects.all()
            credentials = {
                websafe_decode(key.credential_id): {
                    'public_key': key.public_key.encode('utf-8'),
                    'sign_count': key.sign_count,
                } for key in user_keys
            }

            auth_data = server.authenticate_complete(state, credentials, data)

            user_key = UserKey.objects.get(credential_id=websafe_encode(auth_data.credential_id).decode())
            user_key.sign_count = auth_data.new_sign_count
            user_key.save()

            del request.session['fido2_state']
            return JsonResponse({"status": "Authentication successful"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({'error': 'POST method required'}, status=405)
