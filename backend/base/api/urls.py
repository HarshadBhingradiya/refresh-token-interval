from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('', views.getRoutes),
    path('notes/', views.getNotes),

    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('register/', views.RegisterView.as_view(), name='auth_register'),
    path("login/", views.Login.as_view(), name="login_user"),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('change_password/<str:pk>/', views.ChangePasswordView.as_view(), name='auth_change_password'),
    path('logout/', views.LogoutView.as_view(), name='auth_logout'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='main/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="main/password_reset_confirm.html"), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='main/password_reset_complete.html'), name='password_reset_complete'), 
    path("password_reset/", views.PasswordReset.as_view(), name="password_reset"),
]
