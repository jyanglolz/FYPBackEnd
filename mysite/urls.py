from django.urls import include,path
from mysite import views
from django.views.generic import TemplateView
from rest_framework.authtoken.views import obtain_auth_token
app_name = 'mysite'

urlpatterns = [
    path('signup', views.signup),
    path('checkusername', views.checkUsername),
    path('adminsignup', views.adminsignup),
    path('signin', views.signin),
    path('gettoken', obtain_auth_token, name='token_obtain_pair'),
    path('accounts/', include('django.contrib.auth.urls')),  # Include Django's built-in authentication URLs
    path('forgotpassword', views.forgotPassword),
    path('resetpassword', views.resetPassword),
    path('authenticateuserwithtoken', views.authenticateUserWithToken),
    path('sendverificationemail', views.sendVerificationEmail),
    path('verifyverificationcode', views.verifyVerificationCode),
    path('createtask', views.createTask),
    path('getalltasks', views.getAllTasks),
    path('edittask', views.editTask),
    path('deletetask', views.deleteTask),
    path('getuserdata', views.getUserData),
    path('getalluserdata', views.getAllUserData),
    path('edituserdata', views.editUserData),
    path('deleteuser', views.deleteUser),
]
