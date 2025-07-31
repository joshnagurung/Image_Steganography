from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', home, name='home'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('encryption', encryption_view, name='encryption'),
    path('decryption', decryption_view, name='decryption'),
    path('logout/', logout_view, name='logout'),
    path('about/', about, name='about'),
    path('generate/', generate_qr, name='generate_qr_enc'),
    path('decrypt/', decrypt, name='decrypt_qr'),
    path('generateqrtext/', generate_qr_text, name='generate_qr')
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)