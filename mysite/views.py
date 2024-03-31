# myapp/views.py
from django.http import HttpResponse
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from rest_framework.response import Response
from django.shortcuts import render
from django.contrib.auth.models import User
# from rest_framework import generics
from rest_framework.decorators import api_view, permission_classes
from .serializers import UserSerializer, TaskSerializer, EditUserSerializer
import json
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
# from .utils import isValidToken
from django.contrib.auth.decorators import login_required
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import make_password
from django.utils import timezone
#import model
from .models import VerificationCode, Task
from . import serializers
#send mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils.crypto import get_random_string
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# Create your views here.


@api_view(['POST'])
def signup(request):
    # Copy the mutable version of request.POST
    data = request.POST.copy()

    # Hash the password
    data['password'] = make_password(data['password'])

    # Now you can use the mutable data for further processing
    serializer = UserSerializer(data=data)

    if serializer.is_valid():
        serializer.save()
        return Response({'message': 'User signed up successfully!'}, status=201)

    return Response(serializer.errors, status=400)

@api_view(['POST'])
def adminsignup(request):
    # Copy the mutable version of request.POST
    data = request.POST.copy()

    # Hash the password
    data['password'] = make_password(data['password'])

    # Set staff and superuser status to yes
    data['is_staff'] = 'true'
    # data['is_superuser'] = 'true'
    # Now you can use the mutable data for further processing
    serializer = UserSerializer(data=data)

    if serializer.is_valid():
        serializer.save()
        return Response({'message': 'Admin signed up successfully!'}, status=201)

    return Response(serializer.errors, status=400)

@api_view(['POST'])
def checkUsername(request):
    username = request.data.get('username', '')

    # Check if the username already exists in the database
    if User.objects.filter(username=username).exists():
        return Response({'valid': False, 'message': 'Username already exists'}, status=200)

    return Response({'valid': True, 'message': 'Username is valid'}, status=200)


@csrf_exempt
def signin(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username', '')
        password = data.get('password', '')

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Login the user
            login(request, user)

            # Generate verification code
            verification_code = get_random_string(length=5, allowed_chars='0123456789')

            # Create a VerificationCode instance
            VerificationCode.objects.create(user=user, code=verification_code)

            # Send email for verification
            sendVerificationEmail(user, verification_code)

            return JsonResponse({'message': 'Login successful'})
        else:
            return JsonResponse({'error': 'Invalid username or password'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

def sendVerificationEmail(user, verification_code):
    subject = 'Your Verification Code'
    context = {
        'user': user,
        'verification_code': verification_code,
    }
    message = render_to_string('account_verification_template.html', context)
    plain_message = strip_tags(message)
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = user.email
    send_mail(subject, plain_message, from_email, [to_email], html_message=message)

@csrf_exempt
def verifyVerificationCode(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        # Get the verification code and username from the request data
        verification_code = data.get('verification_code')
        username = data.get('username')
        # print(f"Received verification_code: {verification_code}, username: {username}")
        # Check if the verification code is valid
        try:
            verification_obj = VerificationCode.objects.get(user__username=username, code=verification_code)

            # Check if the verification code is still valid
            if verification_obj.expiryDate >= timezone.now():
                # Check if the entered verification code matches the stored code
                if verification_obj.code == verification_code:
                    # Perform additional actions (e.g., mark email as verified)

                    # Update the user's email verification status
                    UserModel = get_user_model()
                    user = UserModel.objects.get(username=username)
                    # user.is_email_verified = True  # Assuming you have a field like this, i don have
                    user.save()

                    # Delete the used verification code
                    verification_obj.delete()

                    # Assuming you have retrieved user details and token after successful verification
                    token, created = Token.objects.get_or_create(user=user)

                    # Include additional details in the response
                    response_data = {
                        'message': 'Verification successful',
                        'user': {
                            'email': user.email,
                            'first_name': user.first_name,
                            'last_name': user.last_name,
                            'is_staff': user.is_staff,
                        },
                        'token': token.key,
                    }

                    return JsonResponse(response_data)
                else:
                    return JsonResponse({'error': 'Invalid verification code'}, status=400)
            else:
                return JsonResponse({'error': 'Verification code has expired'}, status=400)
        except VerificationCode.DoesNotExist:
            return JsonResponse({'error': 'Invalid verification code'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@api_view(['POST'])
def createTask(request):
    serializer = TaskSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(user=request.user)  # Assuming you're using token authentication
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)

def authenticateUserWithToken(request):
    # Manually get user if there is a token
    the_token = request.META.get('HTTP_AUTHORIZATION')

    if the_token != "undefined" and the_token is not None:
        # Extract the token from the Authorization header
        the_token = the_token.split(" ")[1]
        try:
            # Retrieve user based on the token
            token_obj = Token.objects.get(key=the_token)
            request.user = token_obj.user
        except ObjectDoesNotExist:
            # Invalid token, user might have been logged out or token expired
            return HttpResponse(status=460)
    else:
        # User must be authenticated to access the resource
        return HttpResponse(status=401)

@csrf_exempt
def getAllTasks(request):
    # Authenticate user with token
    auth_result = authenticateUserWithToken(request)
    if auth_result:
        return auth_result  # Return if authentication failed

    if request.method == 'GET':
        user = request.user.id
        # print(user)
        tasks = Task.objects.filter(user=user)
        serializer = TaskSerializer(tasks, many=True)
        # print(tasks)
        return JsonResponse(serializer.data, safe=False)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
def editTask(request):
    auth_result = authenticateUserWithToken(request)
    if auth_result:
        return auth_result  # Return if authentication failed

    try:
        task_id = request.data.get('id')
        task = Task.objects.get(pk=task_id)
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Task.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

@csrf_exempt
def deleteTask(request):
    if request.method == 'POST':
        task_id = request.POST.get('id')
        try:
            task = Task.objects.get(pk=task_id)
            task.delete()
            return JsonResponse({'message': 'Task deleted successfully'}, status=200)
        except Task.DoesNotExist:
            return JsonResponse({'error': 'Task not found'}, status=404)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')

        try:
            user = User.objects.get(email=email, username=username)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

        # Generate password reset token
        token_generator = PasswordResetTokenGenerator()
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Build password reset URL
        reset_url = f"http://localhost:5173/resetpassword/{uid}/{token_generator.make_token(user)}/"

        # Render email template
        email_subject = 'Reset Your Password'
        email_message = render_to_string('email/reset_password.html', {'reset_url': reset_url})

        # Send email
        send_mail(
            email_subject,
            email_message,
            'kongjunyang1@gmail.com',  # Replace with your email address
            [email],
            fail_silently=False,
        )

        return JsonResponse({'message': 'Password reset email sent successfully'}, status=200)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def resetPassword(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        username = request.POST.get('username')
        email = request.POST.get('email')

        # Validate passwords match
        if password != confirm_password:
            return JsonResponse({'error': 'Passwords do not match'}, status=400)

        # Find user by username and email
        user = get_object_or_404(User, username=username, email=email)

        # Set new hashed password
        hashed_password = make_password(password)
        user.password = hashed_password
        user.save()

        return JsonResponse({'message': 'Password reset successfully'}, status=200)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def getUserData(request):
     # Authenticate user with token
    auth_result = authenticateUserWithToken(request)
    if auth_result:
        return auth_result  # Return if authentication failed

    if request.method == 'GET':
        user = request.user  # Assuming authentication is required
        serializer = UserSerializer(user)
        return JsonResponse(serializer.data)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def getAllUserData(request):
     # Authenticate user with token
    auth_result = authenticateUserWithToken(request)
    if auth_result:
        return auth_result  # Return if authentication failed

    if request.method == 'POST':
        users = User.objects.all()
        serializer = serializers.UserSerializer(users, many=True)
        return JsonResponse(serializer.data, status=200, safe=False)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


@api_view(['POST'])
def editUserData(request):
    # Authenticate user with token
    auth_result = authenticateUserWithToken(request)
    if auth_result:
        return auth_result  # Return if authentication failed

    try:
        # Assuming the frontend sends the user ID along with the edited data
        user_id = request.data.get('id')
        user = get_object_or_404(User, pk=user_id)
        serializer = EditUserSerializer(user, data=request.data)  # Use EditUserSerializer for editing
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@csrf_exempt
def deleteUser(request):
    if request.method == 'POST':
        user_id = request.POST.get('id')  # Accessing POST data
        try:
            user = User.objects.get(pk=user_id)
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'}, status=200)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

















# @csrf_exempt
# @login_required
# def getAllTasks(request):
#     if request.method == 'GET':
#         user = request.user
#         print("Authenticated User:", user)  # Print authenticated user for debugging
#         tasks = Task.objects.filter(user=user)
#         print("Number of tasks:", tasks.count())  # Print number of tasks for debugging
#         if tasks.exists():
#             serializer = TaskSerializer(tasks, many=True)
#             return JsonResponse(serializer.data, safe=False)
#         else:
#             return JsonResponse({'message': 'No tasks found for this user'}, status=404)
#     else:
#         return JsonResponse({'error': 'Method not allowed'}, status=405)


# @csrf_exempt
# def verifyVerificationCode(request):
#     if request.method == 'POST':
#         # Get the verification code and username from the request data
#         verification_code = request.POST.get('verification_code')
#         username = request.POST.get('username')

#         # Check if the verification code is valid
#         try:
#             verification_obj = VerificationCode.objects.get(user__username=username, code=verification_code)

#             # Check if the verification code is still valid
#             if verification_obj.expiry_date >= timezone.now():
#                 # Perform any additional actions (e.g., mark email as verified)

#                 # Delete the used verification code
#                 verification_obj.delete()

#                 return JsonResponse({'message': 'Verification successful'})
#             else:
#                 return JsonResponse({'error': 'Verification code has expired'}, status=400)
#         except VerificationCode.DoesNotExist:
#             return JsonResponse({'error': 'Invalid verification code'}, status=400)

#     return JsonResponse({'error': 'Invalid request method'}, status=400)


# @csrf_exempt
# @login_required
# def logout(request):
#     if request.method == 'POST':
#         # Logout the user
#         request.auth.delete()
#         logout(request)
#         return JsonResponse({'message': 'Logout successful'})
#     else:
#         return JsonResponse({'error': 'Invalid request method'}, status=400)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def getUserDetails(request):
#     user = request.user
#     serializer = UserSerializer(user)
#     return Response(serializer.data)


# @login_required
# def checkToken(request):
#     # Extract the token from the request (assuming it's in the headers)
#     token = request.headers.get('Authorization').split()[1]

#     # Check if the token is valid for the current user
#     if isValidToken(request.user, token):
#         # Your logic for the protected view here
#         return JsonResponse({'message': 'You are authenticated!'})
#     else:
#         return JsonResponse({'error': 'Invalid token'}, status=401)