"""
User model extending Django's built-in User.
"""
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom user model for Hadnx."""
    
    # Additional fields for security scanning users
    organization = models.CharField(max_length=255, blank=True)
    
    # Exploitation framework - authorized domains
    authorized_domains = models.JSONField(
        default=list,
        blank=True,
        help_text="List of domains this user is authorized to perform active exploitation on"
    )
    
    # Track user activity
    scans_count = models.IntegerField(default=0)
    last_scan_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return self.email or self.username
