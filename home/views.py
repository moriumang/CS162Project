from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth import authenticate, login, logout, get_backends
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
import json
from .check_ip_reputation import check_ip_reputation
from .check_url_reputation import check_url_reputation
from .check_hash_reputation import check_hash_reputation
from .models import CustomUser  # Assuming CustomUser is the model for your users
import re  # Import regular expressions for additional validations
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
from .utils import send_verification_email, send_otp, generate_otp  # Import OTP sending utility
from datetime import datetime
from django.utils import timezone
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.timezone import now, timedelta
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address
from django.core.validators import URLValidator
from .utils import check_hash_reputation  # Assuming your reputation check function is in utils.py


# Home Page
@login_required(login_url='login')
def HomePage(request):
    return render(request, 'home.html')

# About Page
@login_required(login_url='login')
def AboutPage(request):
    return render(request, 'AboutUs.html')

# Contact Page
@login_required(login_url='login')
def ContactPage(request):
    return render(request, 'ContactUs.html')

# IP Reputation Check
@login_required(login_url='login')
def ipsPage(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address', '').strip()

        # Check if IP address is empty
        if not ip_address:
            messages.error(request, "Please provide an IP address.")
            return render(request, 'ips.html')

        # Validate IP address format (IPv4)
        try:
            validate_ipv4_address(ip_address)  # Validates the IP format
        except ValidationError:
            messages.error(request, "Invalid IP address format. Please enter a valid IPv4 address.")
            return render(request, 'ips.html')

        try:
            # Call the function to check the IP reputation (assuming this is an external call)
            ip_data = check_ip_reputation(ip_address)  # Function that gets reputation info
            ip_data_dict = json.loads(ip_data)  # Assuming it returns JSON data
        except Exception as e:
            messages.error(request, f"Error processing IP reputation check: {str(e)}")
            return render(request, 'ips.html')

        # If everything is fine, pass the reputation data to the report page
        return render(request, 'ip_report.html', {'ip_data': ip_data_dict})

    # If not a POST request, render the input page
    return render(request, 'ips.html')

# URL Reputation Check
@login_required(login_url='login')
def urlsPage(request):
    if request.method == 'POST':
        url = request.POST.get('url', '').strip()

        # Check if URL is empty
        if not url:
            messages.error(request, "Please provide a URL.")
            return render(request, 'urls.html')

        # Validate the URL format
        validate = URLValidator()
        try:
            validate(url)  # This will raise ValidationError if the URL is invalid
        except ValidationError:
            messages.error(request, "Invalid URL format. Please enter a valid URL.")
            return render(request, 'urls.html')

        try:
            # Assuming the function 'check_url_reputation' returns the reputation data as a JSON string
            url_data = check_url_reputation(url)
            url_data_dict = json.loads(url_data)  # Parse the JSON response
        except Exception as e:
            messages.error(request, f"Error processing URL reputation check: {str(e)}")
            return render(request, 'urls.html')

        # If everything goes fine, render the report page
        return render(request, 'url_report.html', {'url_data': url_data_dict})

    # If it's not a POST request, render the input page
    return render(request, 'urls.html')

# Hash Reputation Check
@login_required(login_url='login')
def hashesPage(request):
    if request.method == 'POST':
        hash_value = request.POST.get('hash_value')

        if not hash_value:
            messages.error(request, "Please provide a hash value.")
            return render(request, 'hashes.html')

        # Strip extra spaces and sanitize input
        hash_value = hash_value.strip()

        # Validate hash format (MD5, SHA1, or SHA256)
        if not validate_hash_format(hash_value):
            messages.error(request, "Invalid hash format. Please enter a valid MD5, SHA1, or SHA256 hash.")
            return render(request, 'hashes.html')

        try:
            # Call the reputation check function
            hash_data = check_hash_reputation(hash_value)
            hash_data_dict = json.loads(hash_data)
        except Exception as e:
            # Handle error if the reputation check fails
            messages.error(request, "Error processing hash reputation check.")
            return render(request, 'hashes.html')

        return render(request, 'hash_report.html', {'hash_data': hash_data_dict})
    
    return render(request, 'hashes.html')

def validate_hash_format(hash_value):
    # Regular expressions for common hash types (MD5, SHA1, SHA256)
    hash_patterns = {
        'md5': r'^[a-f0-9]{32}$',         # MD5 hashes (32 characters, hex)
        'sha1': r'^[a-f0-9]{40}$',        # SHA1 hashes (40 characters, hex)
        'sha256': r'^[a-f0-9]{64}$'       # SHA256 hashes (64 characters, hex)
    }

    # Check for valid MD5, SHA1, or SHA256 hash formats
    if re.match(hash_patterns['md5'], hash_value):
        return 'md5'
    elif re.match(hash_patterns['sha1'], hash_value):
        return 'sha1'
    elif re.match(hash_patterns['sha256'], hash_value):
        return 'sha256'
    return None

# Signup Page
def signup_view(request):
    if request.method == 'POST':
        uname = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')

        # Validations for username, email, and passwords
        if pass1 != pass2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html')

        if not re.match(r'^[\w]+$', uname):
            messages.error(request, "Username can only contain letters, numbers, and underscores.")
            return render(request, 'signup.html')

        if CustomUser.objects.filter(username=uname).exists():
            messages.error(request, "Username already taken.")
            return render(request, 'signup.html')

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already in use.")
            return render(request, 'signup.html')

        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            messages.error(request, "Invalid email format.")
            return render(request, 'signup.html')

        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[A-Z])(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', pass1):
            messages.error(request, "Password must be at least 8 characters long and contain one uppercase letter, one number, and one special character.")
            return render(request, 'signup.html')

        # If all validations pass, create the user
        user = CustomUser.objects.create_user(username=uname, email=email, password=pass1)
        user.is_active = False  # Mark user as inactive initially
        user.save()

        # Send verification email (ensure to pass the request object)
        send_verification_email(user, request)  # Passing the request object here

        messages.success(request, "Account created successfully! Please check your email to activate your account.")
        return redirect('login')

    return render(request, 'signup.html')


# Email Activation View
def verify_email(request, uidb64, token):
    try:
        # Decode the user ID from the base64 string
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if not user.is_verified:
            user.is_verified = True  # Update the is_verified field
            user.is_active = True  # Keep is_active True for compatibility
            user.save()
            messages.success(request, "Your account has been activated. You can now log in.")
        else:
            messages.info(request, "Your email is already verified.")
        return redirect('login')
    else:
        messages.error(request, "The activation link is invalid or has expired.")
        return redirect('login')

# Define the OTP expiry time, e.g., 5 minutes
OTP_EXPIRY_TIME = 300  # 5 minutes in seconds

def login_view(request):
    if request.method == 'POST':
        # Get the form data
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        # Validate inputs
        if not username or not password:
            messages.error(request, "Username and password cannot be empty.")
            return redirect('login')

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user:
            # Allow superusers and staff to bypass OTP verification
            if user.is_superuser or user.is_staff:
                login(request, user)
                messages.success(request, "Logged in successfully as admin!")
                return redirect('admin:index')  # Redirect to admin dashboard

            # Regular users: Generate OTP and set expiry time
            otp = generate_otp()
            user.otp = otp
            user.otp_expiry_time = now() + timedelta(seconds=OTP_EXPIRY_TIME)
            user.save()

            # Send OTP via email
            send_otp(user, otp)

            # Store username in session for OTP verification
            request.session['username'] = username

            # Redirect to OTP verification page
            return redirect('verify_otp')  # Adjust the name to match your URL pattern
        else:
            # Invalid credentials
            messages.error(request, "Invalid username or password.")
            return redirect('login')

    return render(request, 'login.html')



# OTP Verification View
def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')

        # Retrieve username from session
        username = request.session.get('username')

        if not username:
            messages.error(request, "Session expired. Please log in again.")
            return redirect('login')

        try:
            user = CustomUser.objects.get(username=username)

            # Admin and staff bypass OTP verification
            if user.is_superuser or user.is_staff:
                # Set the backend explicitly for admin/staff
                backend = get_backends()[0]  # Use the first backend from your settings
                user.backend = f"{backend.__module__}.{backend.__class__.__name__}"

                login(request, user)
                messages.success(request, "Logged in successfully as admin!")
                return redirect('admin:index')

            # Check if OTP matches and is not expired
            if user.otp == otp:
                # OTP expiry logic
                if user.otp_expiry_time and now() > user.otp_expiry_time:
                    messages.error(request, "OTP has expired. Please request a new one.")
                    return redirect('resend_otp')  # Adjust to match your resend OTP logic

                # Set the backend explicitly if OTP is valid
                backend = get_backends()[0]  # Use the first backend from your settings
                user.backend = f"{backend.__module__}.{backend.__class__.__name__}"

                # Log the user in
                login(request, user)

                # Clear session data (remove 'username' from session after successful login)
                request.session.pop('username', None)

                messages.success(request, "Logged in successfully!")
                return redirect('home')  # Redirect to the homepage or dashboard
            else:
                messages.error(request, "Invalid OTP. Please try again.")
                return render(request, 'verify_otp.html', {'username': username})

        except CustomUser.DoesNotExist:
            messages.error(request, "User does not exist.")
            return redirect('login')

    return render(request, 'verify_otp.html')

# Resend OTP View
def resend_otp(request):
    # If method is POST (when user submits the form)
    if request.method == 'POST':
        # Get the username from the form
        username = request.POST.get('username', '').strip()

        if not username:
            messages.error(request, "Username is required.")
            return redirect('verify_otp')  # Redirect to OTP verification page

        try:
            # Fetch the user based on the username
            user = CustomUser.objects.get(username=username)

            # Only allow resending OTP if the user is verified or allowed
            if user.is_verified or user.is_superuser or user.is_staff:
                # Generate and send a new OTP
                otp = generate_otp()  # Replace with your OTP generation function
                user.otp = otp
                user.save()
                send_otp(user, otp)  # Send the new OTP to the user's email

                # Store the username in the session so it can be accessed for verification
                request.session['username'] = username

                messages.success(request, "A new OTP has been sent to your email.")
                return redirect('verify_otp')  # Redirect to OTP verification page

            else:
                messages.error(request, "Please verify your email before requesting an OTP.")

        except CustomUser.DoesNotExist:
            messages.error(request, "User not found.")

        return redirect('verify_otp')

    # If method is not POST, redirect to the login page
    return redirect('login')



# Logout Page
def LogoutPage(request):
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('login')


#Date Time
def send_verification_email(user, request):
    current_site = get_current_site(request)
    subject = "Verify Your Email - Threat Hunter 360"
    context = {
        'user': user,
        'link': f"http://{current_site.domain}/verify-email/{urlsafe_base64_encode(bytes(str(user.pk), encoding='utf-8'))}/{default_token_generator.make_token(user)}",
        'current_year': datetime.now().year,
    }
    message = render_to_string('email_verification.html', context)
    send_mail(
        subject,
        "",
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=message
    )


def send_verification_email(user, request):
    # Generate a token and uid for the user
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    
    # Get the domain and create the verification link
    current_site = get_current_site(request)
    verification_link = f"http://{current_site.domain}{reverse('verify_email', args=[uid, token])}"

    # Create the email content
    subject = 'Email Verification'
    message = render_to_string('email_verification.html', {
        'user': user,
        'verification_link': verification_link,
    })

    # Send the email
    send_mail(subject, message, 'from@example.com', [user.email])