from django.contrib import admin

# Register your models here.
from .models import VerificationCode, Task


class VerificationCodeAdmin(admin.ModelAdmin):
    list_display=['user', 'code','dateSent','expiryDate']

class TaskAdmin(admin.ModelAdmin):
    list_display=['id','title', 'description','createdAt','dueDate','completed','user']


admin.site.register(VerificationCode,VerificationCodeAdmin)
admin.site.register(Task,TaskAdmin)

