from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.core.exceptions import ImproperlyConfigured
import random
import string
import requests  # Assuming you're using requests for the reputation check


# Function to send the email verification link
def send_verification_email(user, request):
    # Generate the token for the user
    token = default_token_generator.make_token(user)

    # Get the UID of the user, encode it to base64
    uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))  # Ensure encoding to bytes

    # Generate the verification URL
    verify_url = reverse('verify_email', kwargs={'uidb64': uid, 'token': token})

    # Ensure SITE_URL is defined in settings.py
    try:
        site_url = settings.SITE_URL
    except AttributeError:
        raise ImproperlyConfigured("SITE_URL is not defined in settings.py")

    # Complete the verification link
    link = f"{site_url}{verify_url}"

    # Prepare the email message content using the email template
    try:
        message = render_to_string('email/verify_email.html', {
            'user': user,
            'link': link,
        })
    except Exception as e:
        raise ImproperlyConfigured(f"Error rendering verification email template: {str(e)}")

    # Set up the email subject and send the email
    email_subject = "Verify your email address"
    send_mail(email_subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


# Function to generate OTP (One-Time Password)
def generate_otp():
    """Generate a random 6-digit OTP."""
    otp = ''.join(random.choices(string.digits, k=6))  # Generates a 6-digit OTP
    return otp


# Function to send the OTP to the user's email
def send_otp(user, otp):
    """Send OTP via email to the user."""
    # Prepare the OTP message content
    message = f"Your OTP for verification is: {otp}"

    try:
        email_subject = "Your OTP Verification"
        # Send OTP via email
        send_mail(email_subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
    except Exception as e:
        raise ImproperlyConfigured(f"Error sending OTP email: {str(e)}")


# Optional: If you want to send an OTP immediately after login or another action,
# you can now call generate_otp() and send_otp(user, otp) in your views.


def check_hash_reputation(hash_value):
    # Example of a function that checks hash reputation
    url = f"https://someapi.com/check/{hash_value}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception("Error checking hash reputation")