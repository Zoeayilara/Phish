from django.db import models
from django.utils import timezone

class Email(models.Model):
    STATUS_CHOICES = [
        ('phishing', 'Phishing'),
        ('suspicious', 'Suspicious'),
        ('safe', 'Safe'),
        ('pending', 'Pending'),
    ]

    sender = models.EmailField(max_length=255)
    sender_domain = models.CharField(max_length=255, blank=True)
    subject = models.CharField(max_length=500)
    body = models.TextField()
    received_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    # ML results
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    risk_score = models.FloatField(default=0.0)

    # Feature scores (0-1)
    text_score = models.FloatField(default=0.0)
    url_score = models.FloatField(default=0.0)
    metadata_score = models.FloatField(default=0.0)
    attachment_score = models.FloatField(default=0.0)

    # Extracted features
    extracted_urls = models.JSONField(default=list)
    has_attachment = models.BooleanField(default=False)
    attachment_name = models.CharField(max_length=255, blank=True)
    why_flagged = models.TextField(blank=True)

    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-received_at']

    def __str__(self):
        return f"[{self.status.upper()}] {self.subject[:60]}"

    @property
    def risk_percent(self):
        return round(self.risk_score * 100)

    @property
    def text_score_pct(self):
        return round(self.text_score * 100)

    @property
    def url_score_pct(self):
        return round(self.url_score * 100)

    @property
    def metadata_score_pct(self):
        return round(self.metadata_score * 100)

    @property
    def attachment_score_pct(self):
        return round(self.attachment_score * 100)


class ScanLog(models.Model):
    email = models.ForeignKey(Email, on_delete=models.CASCADE, related_name='logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
    level = models.CharField(max_length=20, default='info')  # info, warning, danger

    class Meta:
        ordering = ['-timestamp']
