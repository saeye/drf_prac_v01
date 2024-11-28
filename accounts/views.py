from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_200_OK
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate
from django.contrib.auth import login
from rest_framework.decorators import permission_classes

# User 모델 가져오기
User = get_user_model() 

# 회원가입 (토큰인증)
@api_view(['POST'])
def register(request):

    # 필수 필드 검증
    required_fields = ['username', 'email', 'password'] # 필수 필드
    missing_fields = [] # 누락된 필드

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
