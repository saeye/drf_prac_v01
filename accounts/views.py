from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_200_OK, HTTP_401_UNAUTHORIZED
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate
from django.contrib.auth import login
from rest_framework.decorators import permission_classes
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from .serializers import UserProfileSerializer
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import csrf_exempt

# User 모델 가져오기
User = get_user_model() 

# 회원가입 (토큰인증)
@api_view(['POST'])
def register(request):

    # 필수 필드 검증
    required_fields = ['username', 'email', 'password'] # 필수 필드
    missing_fields = [] # 누락된 필드 저장할 리스트

    for field in required_fields: # 필수 필드 반복
        if not request.data.get(field): # 현재 필드에 request.data가 없거나 값이 비어있으면
            missing_fields.append(field) # 누락된 필드 리스트에 추가

    if missing_fields: # 누락된 필드가 있으면
        return Response({"error": f"{', '.join(missing_fields)}(을)를 입력해주세요."}, status=HTTP_400_BAD_REQUEST) # 에러 메시지 반환
    
    # 데이터 가져오기
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    # 중복 확인 및 메시지 반환
    if User.objects.filter(username=username).exists():
        return Response({"error": "이미 사용 중인 username입니다."}, status=HTTP_400_BAD_REQUEST)
    if User.objects.filter(email=email).exists():
        return Response({"error": "이미 사용 중인 email입니다."}, status=HTTP_400_BAD_REQUEST)

    # 유저 생성
    user = User.objects.create_user(username=username, email=email, password=password)

    # 회원가입 성공 시 반환되는 response
    return Response({"message": "회원가입 완료👌",}, status=HTTP_201_CREATED)


# 로그인 (토큰인증)
@api_view(['POST'])
def login(request):

    # 데이터 가져오기
    username = request.data.get('username')
    password = request.data.get('password')

    # 필수 필드 검증
    if not username and not password:
        return Response({"error": "유저네임과 패스워드를 입력해주세요."}, status=HTTP_400_BAD_REQUEST)
    if not username:
        return Response({"error": "유저네임을 입력해주세요"}, status=HTTP_400_BAD_REQUEST)
    if not password:
        return Response({"error": "패스워드를 입력해주세요."}, status=HTTP_400_BAD_REQUEST)

    # 유저 인증
    user = authenticate(username=username, password=password)

    # 인증 실패 시
    if user is None:
        if not User.objects.filter(username=username).exists(): # 유저네임 있는지 확인
            return Response({"error": "username 틀림🥲 다시 입력하세요."}, status=HTTP_400_BAD_REQUEST) # 유저네임 잘못된 경우 에러메시지
        return Response({"error": "password 틀림😟 다시 입력하세요."}, status=HTTP_400_BAD_REQUEST) # 패스워드 잘못된 경우 에러메시지
    
    # 토큰 발급
    refresh = RefreshToken.for_user(user)

    # 로그인 성공 시 반환되는 response
    return Response({
        "message": "로그인 성공👌",
        "access": str(refresh.access_token),  # Access Token 발급
        "refresh": str(refresh),  # Refresh Token 발급
    }, status=HTTP_200_OK)

# 로그아웃 (토큰인증)
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # 로그인 한 유저만
def logout(request):

    refresh_token = request.data.get('refresh') # refresh token 가져오기

    if not refresh_token: # refresh token 없을 시
        return Response({"error": "refresh token이 필요합니다."}, status=HTTP_400_BAD_REQUEST) # 에러메시지 반환
    
    try: 
        token = RefreshToken(refresh_token) # refresh token 객체 생성
        token.blacklist()  # refresh token 블랙리스트에 추가
    
    except Exception: # 유효하지 않은 토큰 예외처리
        return Response({"error": "유효하지 않은 토큰입니다."}, status=HTTP_400_BAD_REQUEST)  # 에러 메시지 반환

    # 로그아웃 성공 시 반환되는 response
    return Response({"message": "로그아웃 성공👌"}, status=HTTP_200_OK)

# 유저 프로필 조회 및 수정
@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])  # 로그인한 유저만
def user_profile(request):
    user = request.user  # 현재 인증된 유저

    if request.method == 'GET':
        # 프로필 조회
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=HTTP_200_OK)

    elif request.method == 'PUT':
        # 프로필 수정
        serializer = UserProfileSerializer(user, data=request.data, partial=True)  # 부분 업데이트 허용
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

# 비밀번호 변경
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # 로그인한 유저만
def change_password(request):
    user = request.user  # 현재 인증된 유저

    # 입력 필드 가져오기
    current_password = request.data.get('current_password')
    new_password = request.data.get('new_password')
    new_password_confirm = request.data.get('new_password_confirm')

    # 필수 필드 검증
    if not current_password or not new_password or not new_password_confirm:
        return Response({"error": "현재 비밀번호와 새로운 비밀번호를 모두 입력해주세요."}, status=HTTP_400_BAD_REQUEST)

    # 현재 비밀번호 확인
    if not user.check_password(current_password):
        return Response({"error": "현재 비밀번호가 일치하지 않습니다."}, status=HTTP_400_BAD_REQUEST)

    # 새 비밀번호 확인
    if new_password != new_password_confirm:
        return Response({"error": "새 비밀번호가 일치하지 않습니다."}, status=HTTP_400_BAD_REQUEST)

    # 비밀번호 변경
    user.set_password(new_password)
    user.save()

    # 성공 메시지 반환
    return Response({"message": "비밀번호가 변경되었습니다."}, status=HTTP_200_OK)


# 회원가입 (세션인증)
@api_view(['POST'])
@permission_classes([AllowAny])  # 모든 사용자 접근 가능
def register_with_session(request):
    # 데이터 가져오기
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    # 필수 필드 검증
    if not username:
        return Response({"error": "유저네임을 입력해주세요."}, status=HTTP_400_BAD_REQUEST)
    if not email:
        return Response({"error": "이메일을 입력해주세요."}, status=HTTP_400_BAD_REQUEST)
    if not password:
        return Response({"error": "패스워드를 입력해주세요."}, status=HTTP_400_BAD_REQUEST)

    # 중복 확인
    if User.objects.filter(username=username).exists():
        return Response({"error": "이미 사용 중인 username입니다."}, status=HTTP_400_BAD_REQUEST)
    if User.objects.filter(email=email).exists():
        return Response({"error": "이미 사용 중인 email입니다."}, status=HTTP_400_BAD_REQUEST)

    # 유저 생성
    user = User.objects.create_user(username=username, email=email, password=password)

    # 세션 자동 로그인
    django_login(request, user)

    # 회원가입 성공 메시지 반환
    return Response(
        {
            "message": f"{user.username}님 안녕하세요! 회원가입 및 자동 로그인 되었습니다.",
            "user": {
                "username": user.username,
                "email": user.email,
            }
        },
        status=HTTP_201_CREATED
    )

# 로그인 (세션인증)
@api_view(['POST'])
@permission_classes([AllowAny])  # 모든 사용자 접근 가능

def login_with_session(request):

    # 데이터 가져오기
    username = request.data.get('username')
    password = request.data.get('password')

    # 필수 필드 검증
    missing_fields = [] # 누락된 필드 저장할 리스트
    if not username: # 유저네임 미입력시
        missing_fields.append("유저네임") # 누락된 필드 리스트에 유저네임 추가
    if not password: # 패스워드 미입력시
        missing_fields.append("패스워드") # 누락된 필드 리스트에 패스워드 추가

    if missing_fields: # 누락된 필드 리스트가 존재하면
        return Response({"error": f"{', '.join(missing_fields)}을(를) 입력해주세요."}, status=HTTP_400_BAD_REQUEST) # 누락된 필드 포함한 에러메시지 반환

    # 사용자 인증
    user = authenticate(request=request._request, username=username, password=password)
    if user is None: # 유저가 없으면
        if not User.objects.filter(username=username).exists(): # 유저네임 존재 여부 확인 후 없으면
            return Response({"error": "잘못된 유저네임입니다."}, status=HTTP_401_UNAUTHORIZED) # 유저네임 에러메시지 반환
        # 유저네임은 존재하고 패스워드가 잘못된 경우
        return Response({"error": "패스워드가 틀렸습니다. 다시 입력해주세요."}, status=HTTP_401_UNAUTHORIZED) # 패스워드 에러메시지 반환

    # 세션 로그인 처리 (Django 기본 로그인 함수를 호출하여 세션에 저장)
    django_login(request._request, user) # DRF Request 객체에서 원래 Django HttpRequest를 가져옴

    # 로그인 성공 시 반환
    return Response({
        "message": "로그인 성공👌",
        "user": {
            "username": user.username,
            "email": user.email,
        }
    }, status=HTTP_200_OK)

# 로그아웃 (세션인증)
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # 로그인 한 유저만
def logout_with_session(request):
    django_logout(request._request)  # 세션 로그아웃 처리
    return Response({"message": "로그아웃 성공👌"}, status=HTTP_200_OK)  # 로그아웃 성공 시 메시지

# 프로필 조회, 수정, 비밀번호 변경 (세션 인증)
@api_view(['GET', 'PUT', 'POST'])
@permission_classes([IsAuthenticated])  # 로그인한 유저만
def user_profile_with_session(request):
    user = request.user  # 현재 인증된 유저

    if request.method == 'GET':
        # 프로필 조회
        return Response({
            "username": user.username,
            "email": user.email,
            "introduction": getattr(user, "introduction", None),
            "profile_image": user.profile_image.url if user.profile_image else None
        }, status=HTTP_200_OK)

    elif request.method == 'PUT':
        # 프로필 수정
        email = request.data.get('email', user.email)  # 기존 이메일
        introduction = request.data.get('introduction', user.introduction)  # 기존 자기소개
        profile_image = request.FILES.get('profile_image')  # 업로드된 이미지 파일

        # 중복 이메일 확인
        if User.objects.exclude(pk=user.pk).filter(email=email).exists():
            return Response({"error": "이미 사용 중인 email입니다."}, status=HTTP_400_BAD_REQUEST)

        # 유저 정보 업데이트
        user.email = email
        user.introduction = introduction

        if profile_image:  # 이미지 업로드 시
            user.profile_image = profile_image
        
        user.save()

        return Response({
            "message": "프로필이 성공적으로 수정되었습니다.",
            "user": {
                "username": user.username,
                "email": user.email,
                "introduction": user.introduction,
                "profile_image": user.profile_image.url if user.profile_image else None
            }
        }, status=HTTP_200_OK)

    elif request.method == 'POST':
        # 비밀번호 변경
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        new_password_confirm = request.data.get('new_password_confirm')

        # 필수 필드 검증
        if not current_password or not new_password or not new_password_confirm:
            return Response({"error": "현재 비밀번호와 새로운 비밀번호를 모두 입력해주세요."}, status=HTTP_400_BAD_REQUEST)

        # 현재 비밀번호 확인
        if not user.check_password(current_password):
            return Response({"error": "현재 비밀번호가 일치하지 않습니다."}, status=HTTP_400_BAD_REQUEST)

        # 새 비밀번호 확인
        if new_password != new_password_confirm:
            return Response({"error": "새 비밀번호가 일치하지 않습니다."}, status=HTTP_400_BAD_REQUEST)

        # 비밀번호 변경
        user.set_password(new_password)
        user.save()

        return Response({"message": "비밀번호가 변경되었습니다."}, status=HTTP_200_OK)
