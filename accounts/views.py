from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from django.contrib.auth import login
from rest_framework.decorators import permission_classes

# User 모델 가져오기
User = get_user_model() 

# 회원가입 (토큰인증)
@api_view(['POST'])
def register(request):

    # 회원가입 시 필수 필드
    required_fields = ['username', 'email', 'password']
    # 누락된 필드
    missing_fields = []

    # 필수 필드 반복
    for field in required_fields:
        # 현재 필드에 request.data가 없거나 값이 비어있으면
        if not request.data.get(field):
            # 누락된 필드 리스트에 추가
            missing_fields.append(field)

    # 누락된 필드 에러 메시지 반환
    if missing_fields:
        return Response({"error": f"{', '.join(missing_fields)}(을)를 입력해주세요."}, status=HTTP_400_BAD_REQUEST)
    
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

    # 토큰 발급
    refresh = RefreshToken.for_user(user)

    # 회원가입 성공 시 반환되는 response
    return Response({
        "message": "회원가입 완료👌",
        "refresh": str(refresh),  # Refresh Token 발급
        "access": str(refresh.access_token),  # Access Token 발급
    }, status=HTTP_201_CREATED)


# 회원가입 (세션인증)
@api_view(['POST'])
@permission_classes([AllowAny])  # 모든 사용자 접근 가능
def register_with_session(request):
    # 클라이언트 데이터 가져오기
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

    # 자동 로그인 처리
    user = authenticate(request, username=username, password=password)  # 사용자 인증
    if user is not None:
        login(request, user)  # 세션에 유저 정보 저장

    # 회원가입 성공 시 반환되는 response
    return Response({
        "message": "회원가입 완료👌",
        "user": {
            "username": user.username,
            "email": user.email,
        }
    }, status=HTTP_201_CREATED)
