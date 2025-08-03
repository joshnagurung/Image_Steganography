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


# def encryption_view(request):
#     message = ""
#     error = ""
#     saved_filename = None

#     if request.method == "POST":
#         try:
#             text = request.POST['text']
#             image_file = request.FILES['image']
#             image = Image.open(image_file)

#             if image.mode != 'RGBA':
#                 image = image.convert('RGBA')

#             new_image = hide_text_image(image, text)

#             filename = 'new_' + os.path.splitext(image_file.name)[0] + '.png'
#             # Save inside 'encrypted_images' folder under MEDIA_ROOT
#             save_dir = os.path.join(settings.MEDIA_ROOT, 'encrypted_images')
#             os.makedirs(save_dir, exist_ok=True)
#             image_path = os.path.join(save_dir, filename)

#             new_image.save(image_path, format='PNG')

#             message = "Text has been encrypted in the image."
#             saved_filename = f'encrypted_images/{filename}'  # relative to MEDIA_ROOT

#         except OSError as e:
#             error = f"Image processing error: {str(e)}"
#         except Exception as e:
#             error = f"An unexpected error occurred: {str(e)}"

#     context = {
#         'message': message,
#         'error': error,
#         'stego_image': saved_filename,  # pass filename for display & download
#         'MEDIA_URL': settings.MEDIA_URL,
#     }
#     return render(request, 'encryption/encryption.html', context)





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
# from django.shortcuts import render
# from .forms import GenerateQRForm, DecryptForm
# from cryptography.fernet import Fernet, InvalidToken
# import base64, qrcode
# from io import BytesIO


# def pad_password(password):
#     return base64.urlsafe_b64encode(password.ljust(32)[:32].encode())


# @login_required(login_url='/login')
# def generate_qr(request):
#     qr_img = None
#     if request.method == 'POST':
#         form = GenerateQRForm(request.POST)
#         if form.is_valid():
#             text = form.cleaned_data['text']
#             password = form.cleaned_data['password']
#             key = pad_password(password)
#             fernet = Fernet(key)
#             token = fernet.encrypt(text.encode())

#             # Create QR
#             qr = qrcode.make(token.decode())
#             buffer = BytesIO()
#             qr.save(buffer, format='PNG')
#             img_str = base64.b64encode(buffer.getvalue()).decode()
#             qr_img = f'data:image/png;base64,{img_str}'
#     else:
#         form = GenerateQRForm()
#     return render(request, 'qrapp/generate.html', {'form': form, 'qr_img': qr_img})


# @login_required(login_url='/login')
# def decrypt(request):
#     text = error = None
#     token_val = ''
#     if request.method == 'POST':
#         form = DecryptForm(request.POST)
#         if form.is_valid():
#             token_val = form.cleaned_data['token']
#             password = form.cleaned_data['password']
#             try:
#                 key = pad_password(password)
#                 fernet = Fernet(key)
#                 text = fernet.decrypt(token_val.encode()).decode()
#             except InvalidToken:
#                 error = "Incorrect password or invalid data."
#     else:
#         form = DecryptForm()
#     return render(request, 'qrapp/decrypt.html', {'form': form, 'text': text, 'error': error})




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



#Email Configuration
import os
from django.shortcuts import render
from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from PIL import Image
import logging

# Set up logging
logger = logging.getLogger(__name__)

def encryption_view(request):
    message = ""
    error = ""
    saved_filename = None

    if request.method == "POST":
        try:
            text = request.POST['text']
            image_file = request.FILES['image']
            recipient_email = request.POST.get('email', '').strip()  # Get email from form
            
            # Validate email
            if not recipient_email:
                error = "Please provide an email address to send the encrypted image."
                return render(request, 'encryption/encryption.html', {
                    'error': error,
                    'MEDIA_URL': settings.MEDIA_URL,
                })

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
            saved_filename = f'encrypted_images/{filename}'

            # Send email with encrypted image
            try:
                send_encrypted_image_email(
                    recipient_email=recipient_email,
                    image_path=image_path,
                    filename=filename,
                    original_filename=image_file.name
                )
                message = f"Text has been successfully encrypted in the image and sent to {recipient_email}."
                
            except Exception as email_error:
                logger.error(f"Email sending failed: {str(email_error)}")
                message = "Text has been encrypted in the image, but failed to send email. You can download the image below."
                error = f"Email sending failed: {str(email_error)}"

        except OSError as e:
            error = f"Image processing error: {str(e)}"
            logger.error(f"Image processing error: {str(e)}")
        except Exception as e:
            error = f"An unexpected error occurred: {str(e)}"
            logger.error(f"Unexpected error: {str(e)}")

    context = {
        'message': message,
        'error': error,
        'stego_image': saved_filename,
        'MEDIA_URL': settings.MEDIA_URL,
    }
    return render(request, 'encryption/encryption.html', context)


def send_encrypted_image_email(recipient_email, image_path, filename, original_filename):
    """
    Send encrypted image via email
    """
    try:
        # Email subject and content
        subject = "Your Encrypted Image - Steganography Service"
        
        # Create HTML email content
        html_content = render_to_string('encryption/email_template.html', {
            'original_filename': original_filename,
            'encrypted_filename': filename,
        })
        
        # Create plain text version
        text_content = strip_tags(html_content)
        
        # Create email message
        email = EmailMessage(
            subject=subject,
            body=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient_email],
        )
        
        # Set email content type to HTML
        email.content_subtype = 'html'
        
        # Attach the encrypted image
        with open(image_path, 'rb') as f:
            email.attach(filename, f.read(), 'image/png')
        
        # Send the email
        email.send()
        
        logger.info(f"Encrypted image sent successfully to {recipient_email}")
        
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email}: {str(e)}")
        raise e
    


#Main Flex
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
    email_sent = False
    email_error = None
    
    if request.method == 'POST':
        form = GenerateQRForm(request.POST)
        if form.is_valid():
            text = form.cleaned_data['text']
            password = form.cleaned_data['password']
            recipient_email = form.cleaned_data.get('email', '').strip()
            
            key = pad_password(password)
            fernet = Fernet(key)
            token = fernet.encrypt(text.encode())

            # Create QR
            qr = qrcode.make(token.decode())
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            qr_img = f'data:image/png;base64,{img_str}'
            
            # Send email if email address is provided
            if recipient_email:
                try:
                    send_qr_code_email(
                        recipient_email=recipient_email,
                        qr_image_data=buffer.getvalue(),
                        encrypted_text_preview=text[:50] + "..." if len(text) > 50 else text
                    )
                    email_sent = True
                    messages.success(request, f"QR code has been generated and sent to {recipient_email}")
                except Exception as e:
                    email_error = f"Failed to send email: {str(e)}"
                    logger.error(f"QR email sending failed: {str(e)}")
                    messages.warning(request, "QR code generated successfully, but email sending failed.")
    else:
        form = GenerateQRForm()
    
    return render(request, 'qrapp/generate.html', {
        'form': form, 
        'qr_img': qr_img,
        'email_sent': email_sent,
        'email_error': email_error
    })

def send_qr_code_email(recipient_email, qr_image_data, encrypted_text_preview):
    """
    Send QR code via email
    """
    try:
        # Email subject and content
        subject = "Your Encrypted QR Code - Inkognito"

        # Create HTML email content
        html_content = render_to_string('qrapp/qr_email_template.html', {
            'encrypted_text_preview': encrypted_text_preview,
        })
        
        # Create plain text version
        text_content = strip_tags(html_content)
        
        # Create email message
        email = EmailMessage(
            subject=subject,
            body=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient_email],
        )
        
        # Set email content type to HTML
        email.content_subtype = 'html'
        
        # Attach the QR code image
        email.attach('encrypted_qr_code.png', qr_image_data, 'image/png')
        
        # Send the email
        email.send()
        
        logger.info(f"QR code sent successfully to {recipient_email}")
        
    except Exception as e:
        logger.error(f"Failed to send QR email to {recipient_email}: {str(e)}")
        raise e

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
