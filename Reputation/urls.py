from django.contrib import admin
from django.urls import path, include
from home import views  # Import views from the home app


# Customizing the admin panel headers
admin.site.site_header = 'Threat Hunter 360 Admin'
admin.site.site_title = 'Threat Hunter 360 Admin'
admin.site.index_title = 'Welcome to Threat Hunter 360 Admin'

urlpatterns = [
    # Admin URL
    path('admin/', admin.site.urls),  # Customized admin site path


    # Authentication URLs
    path('signup/', views.signup_view, name='signup'),  # Signup page
    path('verify-email/<uidb64>/<token>/', views.verify_email, name='verify_email'),  # Email verification URL
    path('login/', views.login_view, name='login'),  # Login page
    path('logout/', views.LogoutPage, name='logout'),  # Logout page

    # OTP Verification URL
    path('verify-otp/', views.verify_otp, name='verify_otp'),  # OTP verification page
    path('resend-otp/', views.resend_otp, name='resend_otp'),  # Resend OTP page


    # App-specific URLs
    path('', views.HomePage, name='home'),  # Default to Home page
    path('ips/', views.ipsPage, name='ips'),  # IP reputation check
    path('urls/', views.urlsPage, name='urls'),  # URL reputation check
    path('hashes/', views.hashesPage, name='hashes'),  # Hash reputation check
    path('about/', views.AboutPage, name='about'),  # About Us page
    path('contact/', views.ContactPage, name='contact'),  # Contact Us page

    # Report URLs
    path('ip_report/', views.ipsPage, name='ip_report'),  # IP report
    path('url_report/', views.urlsPage, name='url_report'),  # URL report
    path('hash_report/', views.hashesPage, name='hash_report'),  # Hash report
]
