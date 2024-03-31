from django.db import models
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.utils import timezone
# Create your models here.

class VerificationCode(models.Model):
    def get_expiry_time():
        return timezone.now() + timezone.timedelta(minutes=10)

    def get_random_number():
        return get_random_string(length=5, allowed_chars='0123456789')

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(default=get_random_number, max_length=5)
    dateSent = models.DateTimeField(default=timezone.now)
    expiryDate = models.DateTimeField(default=get_expiry_time, blank=True, help_text="Expires in 10 min by default")

    def __str__(self):
        return self.user.email + " - " + str(self.expiryDate)

class Task(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    createdAt = models.DateTimeField(auto_now_add=True)
    dueDate = models.DateTimeField()
    completed = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title