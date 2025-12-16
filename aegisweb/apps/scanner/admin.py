from django.contrib import admin
from .models import Scan, Finding


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'domain', 'status', 'overall_score', 'grade', 'created_at']
    list_filter = ['status', 'grade', 'created_at']
    search_fields = ['url', 'domain']
    readonly_fields = ['id', 'created_at', 'completed_at']


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ['issue', 'severity', 'category', 'scan']
    list_filter = ['severity', 'category']
    search_fields = ['issue', 'description']
