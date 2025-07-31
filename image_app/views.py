from django.conf import settings
from django.shortcuts import render,  redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from PIL import Image
import stepic
import io
import os
import re

# Create your views here.

@login_required(login_url='/login')
def home(request):
    return render(request, 'dashboard/home.html')



def about(request):
    return render(request, 'about/about.html')



def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        # Regex patterns
        username_pattern = r'^[a-zA-Z0-9_]{3,20}$'
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'

        # Field presence check
        if not username or not password or not confirm_password:
            messages.error(request, "All fields are required.")
        elif not re.match(username_pattern, username):
            messages.error(request, "Username must be 3–20 characters, alphanumeric or underscore.")
        elif not re.match(password_pattern, password):
            messages.error(request, "Password must be at least 8 characters long, include uppercase, lowercase, digit, and symbol.")
        elif password != confirm_password:
            messages.error(request, "Passwords do not match.")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
        else:
            User.objects.create(
                username=username,
                password=make_password(password)
            )
            return redirect('login')

    return render(request, 'auth/register.html')



    
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        if not username or not password:
            messages.error(request, "Both username and password are required.")
        elif not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            messages.error(request, "Invalid username format.")
        else:
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                messages.success(request, f"Welcome back, {user.username}!")
                return redirect('home')
            else:
                messages.error(request, "Invalid username or password.")

    return render(request, 'auth/login.html')




def logout_view(request):
    logout(request)
    return redirect('login')



#LSB Algorithm

def hide_text_image(image, text):
    data = text.encode('utf-8')
    return stepic.encode(image, data)


def encryption_view(request):
    message = ""
    error = ""
    saved_filename = None

    if request.method == "POST":
        try:
            text = request.POST['text']
            image_file = request.FILES['image']
            image = Image.open(image_file)

            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            new_image = hide_text_image(image, text)

            filename = 'new_' + os.path.splitext(image_file.name)[0] + '.png'
            # Save inside 'encrypted_images' folder under MEDIA_ROOT
            save_dir = os.path.join(settings.MEDIA_ROOT, 'encrypted_images')
            os.makedirs(save_dir, exist_ok=True)
            image_path = os.path.join(save_dir, filename)

            new_image.save(image_path, format='PNG')

            message = "Text has been encrypted in the image."
            saved_filename = f'encrypted_images/{filename}'  # relative to MEDIA_ROOT

        except OSError as e:
            error = f"Image processing error: {str(e)}"
        except Exception as e:
            error = f"An unexpected error occurred: {str(e)}"

    context = {
        'message': message,
        'error': error,
        'stego_image': saved_filename,  # pass filename for display & download
        'MEDIA_URL': settings.MEDIA_URL,
    }
    return render(request, 'encryption/encryption.html', context)





def decryption_view(request):
    text = ""
    if request.method == "POST":
        image_file = request.FILES['image']
        image = Image.open(image_file)

        if image.format != 'PNG':
            image = image.convert('RGBA')
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
            image = Image.open(buffer)
        text = extract_text_from_image(image)
    return render(request, 'decryption/decryption.html', locals())



def extract_text_from_image(image):
    data = stepic.decode(image)
    if isinstance(data, bytes):
        return data.decode('utf-8')
    return data



# QR code Main Flex
from django.shortcuts import render
from .forms import GenerateQRForm, DecryptForm
from cryptography.fernet import Fernet, InvalidToken
import base64, qrcode
from io import BytesIO


def pad_password(password):
    return base64.urlsafe_b64encode(password.ljust(32)[:32].encode())


@login_required(login_url='/login')
def generate_qr(request):
    qr_img = None
    if request.method == 'POST':
        form = GenerateQRForm(request.POST)
        if form.is_valid():
            text = form.cleaned_data['text']
            password = form.cleaned_data['password']
            key = pad_password(password)
            fernet = Fernet(key)
            token = fernet.encrypt(text.encode())

            # Create QR
            qr = qrcode.make(token.decode())
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            qr_img = f'data:image/png;base64,{img_str}'
    else:
        form = GenerateQRForm()
    return render(request, 'qrapp/generate.html', {'form': form, 'qr_img': qr_img})


@login_required(login_url='/login')
def decrypt(request):
    text = error = None
    token_val = ''
    if request.method == 'POST':
        form = DecryptForm(request.POST)
        if form.is_valid():
            token_val = form.cleaned_data['token']
            password = form.cleaned_data['password']
            try:
                key = pad_password(password)
                fernet = Fernet(key)
                text = fernet.decrypt(token_val.encode()).decode()
            except InvalidToken:
                error = "Incorrect password or invalid data."
    else:
        form = DecryptForm()
    return render(request, 'qrapp/decrypt.html', {'form': form, 'text': text, 'error': error})




#Flex
from django.shortcuts import render
import qrcode
import io
import base64

def generate_qr_text(request):
    qr_text = ""
    qr_img_base64 = ""

    if request.method == "POST":
        qr_text = request.POST.get('qr_text', '')
        if qr_text:
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_text)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            # Convert image to base64 string to embed in HTML
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            img_str = base64.b64encode(buffer.getvalue()).decode()
            qr_img_base64 = f"data:image/png;base64,{img_str}"

    return render(request, "qrapp/generate_qr.html", {"qr_img_base64": qr_img_base64, "qr_text": qr_text})

