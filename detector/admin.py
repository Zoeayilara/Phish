from django.contrib import admin
from .models import Email, ScanLog

@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    list_display = ('subject', 'sender', 'status', 'risk_percent', 'received_at')
    list_filter = ('status',)
    search_fields = ('sender', 'subject', 'body')
    readonly_fields = ('risk_score', 'text_score', 'url_score',
                       'metadata_score', 'attachment_score', 'why_flagged')

@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ('email', 'level', 'timestamp', 'message')
    list_filter = ('level',)
