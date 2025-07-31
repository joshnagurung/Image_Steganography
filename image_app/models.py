from django.db import models
import uuid

class SecureText(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    text = models.TextField()
    password = models.CharField(max_length=128)
