# contacts/models.py

from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile = models.CharField(max_length=15)
    address = models.TextField()
    password_reset_used = models.BooleanField(default=False)


    def __str__(self):
        return self.user.username

class Contact(models.Model):
    email = models.EmailField()
    mobile = models.CharField(max_length=15)
    address = models.TextField()
    registration_number = models.CharField(max_length=20, unique=True)
    username = models.CharField(max_length=100, default='default_username')

    def __str__(self):
        return self.email


    class Meta:
        app_label = 'contacts'  # Add the app_label attribute

# class Contact(models.Model):
#     registration_number = models.CharField(max_length=20, unique=True)
#     mobile = models.CharField(max_length=15)
#     email = models.EmailField()
#     address = models.TextField()

    def __str__(self):
        return self.registration_number