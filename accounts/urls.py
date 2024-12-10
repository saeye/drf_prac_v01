from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from . import views

urlpatterns = [
    path("signin/", TokenObtainPairView.as_view(), name="token_obtain_pair"), 
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("register/", views.register, name="register"), # 토큰 인증 회원가입
    path("login/", views.login, name="login"), # 토큰 인증 로그인
    path("logout/", views.logout, name="logout"), # 토큰 인증 로그아웃
    path('user_profile/', views.user_profile, name="user_profile"), # 토큰 인증 프로필 조회 및 수정
    path('change_password/', views.change_password, name="change_password"), #툐큰 인증 비밀번호 변경
    path('register_with_session/', views.register_with_session, name='register_with_session'),  # 세션 인증 회원가입
    path('login_with_session/', views.login_with_session, name='login_with_session'),  # 세션 인증 로그인
    path('logout_with_session/', views.logout_with_session, name='logout_with_session'),  # 세션 인증 로그아웃
    path('user_profile_with_session/', views.user_profile_with_session, name='user_profile_with_session'),  # 세션 인증 프로필 조회
]
