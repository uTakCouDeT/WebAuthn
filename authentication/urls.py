from django.urls import path
from . import views

urlpatterns = [
    path('register-device/', views.register_device, name='register_device'),
    path('complete-registration/', views.complete_registration, name='complete_registration'),
    path('authenticate-device/', views.authenticate_device, name='authenticate_device'),
    path('complete-authentication/', views.complete_authentication, name='complete_authentication'),
]
