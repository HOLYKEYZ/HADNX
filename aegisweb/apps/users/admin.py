from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ['username', 'email', 'organization', 'scans_count', 'is_staff', 'date_joined']
    list_filter = ['is_staff', 'is_active', 'date_joined']
    search_fields = ['username', 'email', 'organization']
    
    fieldsets = UserAdmin.fieldsets + (
        ('Hadnx', {'fields': ('organization', 'scans_count', 'last_scan_at')}),
    )
