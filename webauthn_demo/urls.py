"""
URL configuration for webauthn_demo project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path
from authentication import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/start-registration/', views.start_registration, name='start_registration'),
    path('auth/finish-registration/', views.finish_registration, name='finish_registration'),
    path('auth/start-authentication/', views.start_authentication, name='start_authentication'),
    path('auth/finish-authentication/', views.finish_authentication, name='finish_authentication'),
]