from django.contrib import admin
from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'generated_at']
    list_filter = ['generated_at']
    readonly_fields = ['id', 'generated_at']
