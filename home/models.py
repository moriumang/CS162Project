from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.utils.timezone import now

class CustomUser(AbstractUser):
    """
    Custom user model inheriting from AbstractUser.
    Includes email verification status, OTP fields, and custom related names for groups and permissions.
    """

    # Field to track email verification
    is_verified = models.BooleanField(
        default=False,
        help_text="Indicates whether the user's email address has been verified."
    )

    # Fields for OTP authentication
    otp = models.CharField(
        max_length=6, 
        blank=True, 
        null=True, 
        help_text="One-time password for user authentication."
    )
    otp_expiry_time = models.DateTimeField(
        blank=True, 
        null=True, 
        help_text="Expiry time for the OTP."
    )

    # Group and permission fields with custom related names to avoid conflicts
    groups = models.ManyToManyField(
        Group,
        related_name='customuser_groups',  # Custom related_name to avoid conflict
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups"
    )
    
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_permissions',  # Custom related_name to avoid conflict
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions"
    )

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ['username']  # Users are ordered by username by default

    def is_otp_valid(self):
        """
        Checks if the OTP is valid and not expired.
        """
        if self.otp and self.otp_expiry_time:
            return now() <= self.otp_expiry_time
        return False
