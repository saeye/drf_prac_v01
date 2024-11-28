from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    # 유저네임 (20자로 제한, 중복 불가)
    username = models.CharField(max_length=20, unique=True) 
    # 이메일 (중복 불가)
    email = models.EmailField(unique=True)
    # 가입 날짜 (자동 저장)
    date_joined = models.DateField(auto_now_add=True) 
    # 자기소개 (텍스트 입력, 선택 사항)
    introduction = models.TextField(null=True, blank=True)
    # 프로필 이미지 (이미지 파일, 선택 사항)
    profile_image = models.ImageField(upload_to="profile_images/", null=True, blank=True)
    # 계정의 활성화 여부 
    is_active = models.BooleanField(default=True)
    # 블랙리스트 여부
    is_blacklist = models.BooleanField(default=False)

    # 유저 출력시 유저네임으로 반환
    def __str__(self):
        return self.username
 