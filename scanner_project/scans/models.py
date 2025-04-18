from django.db import models
from django.contrib.auth.models import User

class Scan(models.Model):
    STATUS_CHOICES = [
        ('queued', 'Queued'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('error', 'Error'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    target = models.URLField()
    scan_type = models.CharField(max_length=50, default='Full Scan')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    created_at = models.DateTimeField(auto_now_add=True)

    # Результаты
    open_ports = models.TextField(blank=True)
    sql_injection = models.BooleanField(null=True)
    xss = models.BooleanField(null=True)
    csrf = models.BooleanField(null=True)
    directory_traversal = models.BooleanField(null=True)
    security_headers = models.TextField(blank=True)
    error_message = models.TextField(blank=True)

    def __str__(self):
        return f"{self.target_url} ({self.status})"
