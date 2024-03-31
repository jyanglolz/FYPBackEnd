# mysite/serializers.py
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Task


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'first_name', 'last_name', 'is_staff', 'last_login', 'date_joined')
        extra_kwargs = {'password': {'write_only': True}}

class TaskSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'createdAt', 'dueDate', 'completed', 'user']

class EditUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'last_login', 'date_joined')