import imghdr
import re

from django.contrib.auth.hashers import check_password, make_password
from rest_framework import status, exceptions
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect

from .serializers import *
from .utils import *
from .models import CustomUser as User, Document, Language, Hobby, Skill, Address, Framework, DBMS


def home(request):
    user = User.objects.get(id=1)
    user = UserSerializer(user, many=False)
    languages = Language.objects.all()
    languages = LanguageSerializer(languages, many=True)
    frameworks = Framework.objects.all()
    frameworks = FrameworkSerializer(frameworks, many=True)
    databases = DBMS.objects.all()
    databases = DBMSSerializer(databases, many=True)
    hobbies = Hobby.objects.all()
    hobbies = HobbySerializer(hobbies, many=True)
    skills = Skill.objects.all()
    skills = SkillSerializer(skills, many=True)

    jobs = Work.objects.all()
    jobs = WorkSerializer(jobs, many=True)

    projects = Project.objects.all()
    projects = ProjectSerializer(projects, many=True)

    degrees = Education.objects.all()
    degrees = EducationSerializer(degrees, many=True)

    context = {'user': user.data, 'languages': languages.data, 'frameworks': frameworks.data,
               'databases': databases.data, 'hobbies': hobbies.data, 'skills': skills.data, 'jobs': jobs.data,
               'projects': projects.data, 'degrees': degrees.data}
    return render(request, 'home.html', context)


def admin(request):
    return render(request, 'admin.html')


@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login(request):
    """
    View to log in
    """
    if not request.data.get('email', None):
        return Response("email not provided", status=status.HTTP_400_BAD_REQUEST)

    if not request.data.get('password', None):
        return Response("password not provided", status=status.HTTP_400_BAD_REQUEST)

    users = User.objects.all().filter(email=request.data['email'])
    if not users.exists():
        return Response("Email does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(email=request.data['email'])
    if not check_password(request.data['password'], user.password):
        return Response("Incorrect password", status=status.HTTP_400_BAD_REQUEST)

    user.token_last_expired = timezone.now()
    user.authenticated = False
    user.security_code = generate_security_code()
    user.is_active = True
    user.save()

    serializer = UserSerializer(user, many=False)

    if request.data.get('remember', None):
        access_token = generate_access_token(user, True)
    else:
        access_token = generate_access_token(user, False)

    refresh_token = generate_refresh_token(user, False, False)

    response = Response()
    response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
    response.data = {
        'token': access_token,
        'user': serializer.data,
    }
    return response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def two_factor_auth(request):
    """
    View to send 2 factor authentication security code
    """
    user_id = request.user.id
    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return Response("User does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=user_id)
    if user.authenticated:
        return Response("Already authenticated", status=status.HTTP_400_BAD_REQUEST)

    user.security_code = generate_security_code()
    user.save()

    email_2fa(user)

    return Response("Security code sent successfully", status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def authenticate(request):
    """
    View to authenticate user using 2 factor authentication
    """
    user_id = request.user.id
    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=user_id)
    if user.authenticated:
        return Response("already authenticated", status=status.HTTP_400_BAD_REQUEST)

    security_code = request.data.get('security_code', None)
    if not security_code:
        return Response("no security code provided", status=status.HTTP_400_BAD_REQUEST)

    if security_code != user.security_code:
        return Response("incorrect code", status=status.HTTP_400_BAD_REQUEST)
    user.authenticated = True
    user.security_code = None
    user.save()
    return Response("authentication successful", status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def logout(request):
    """
    View to log out
    """
    user_id = request.user.id
    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=user_id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)
    user.token_last_expired = timezone.now()
    user.security_code = None
    user.authenticated = False
    user.is_active = False
    user.save()
    return Response(status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_details(request):
    """
    View to get details
    """
    users = User.objects.all().filter(id=1)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=1)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)
    serializer = UserSerializer(user, many=False)
    return Response(serializer.data)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def update_details(request):
    """
    View to update user details
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    if request.data.get('name', None):
        name = request.data['name']
        user.name = name
        user.save()

    if request.data.get('surname', None):
        surname = request.data['surname']
        user.surname = surname
        user.save()

    if request.data.get('number', None):
        number = request.data['number']
        user.number = number
        user.save()

    if request.data.get('email', None):
        email = request.data['email']
        if User.objects.all().filter(email=email).exists():
            return Response("email already exists", status=status.HTTP_400_BAD_REQUEST)
        temp = User(id=user.id, email=email, name=user.name, surname=user.surname,
                    number=user.number, password=user.password)
        send_email_verification_link(temp, request)

    return Response("Successfully updated user details. If you have changed your email address, it will have to be "
                    "verified in order for it to be updated",
                    status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def reset_password(request):
    """
    View to reset password
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    if not request.data.get('old_password', None):
        return Response("old password not provided", status=status.HTTP_400_BAD_REQUEST)

    if not request.data.get('new_password', None):
        return Response("new password not provided", status=status.HTTP_400_BAD_REQUEST)

    if not request.data.get('repeat_password', None):
        return Response("repeated password not provided", status=status.HTTP_400_BAD_REQUEST)

    password = user.password
    if not check_password(request.data['old_password'], password):
        return Response("incorrect password", status=status.HTTP_400_BAD_REQUEST)

    if not re.search("^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W).{12,}$", request.data['new_password']):
        return Response("invalid password", status=status.HTTP_400_BAD_REQUEST)

    if request.data['new_password'] != request.data['repeat_password']:
        return Response("passwords don't match", status=status.HTTP_400_BAD_REQUEST)

    user.password = make_password(request.data['new_password'])
    user.save()

    return Response("password has been reset", status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def send_forgot_password_link(request):
    """
    View to send forgot password link
    """
    email = request.GET.get('email')
    if email:
        users = User.objects.all().filter(email=email)
        if not users.exists():
            return Response("email does not exist", status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(email=email)

        send_forgot_password_email(user, request)

        return Response(status=status.HTTP_200_OK)
    else:
        return Response("no email provided", status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@permission_classes([AllowAny])
def reset_forgotten_password(request):
    """
    View to reset forgotten password
    """
    token = request.GET.get('token')
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(id=payload['user_id'])

        if not request.data.get('password', None):
            return Response("password not provided", status=status.HTTP_400_BAD_REQUEST)

        if not request.data.get('repeat_password', None):
            return Response("repeated password not provided", status=status.HTTP_400_BAD_REQUEST)

        if not re.search("^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W).{12,}$", request.data['password']):
            return Response("invalid password", status=status.HTTP_400_BAD_REQUEST)

        if request.data['password'] != request.data['repeat_password']:
            return Response("passwords don't match", status=status.HTTP_400_BAD_REQUEST)

        user.password = make_password(request.data['password'])
        user.save()

        return render(request, "success.html")
    except jwt.ExpiredSignatureError:
        return render(request, "expired.html")
    except jwt.exceptions.DecodeError:
        return render(request, "invalid.html")


@api_view(['GET'])
@permission_classes([AllowAny])
def render_forgotten_password_page(request):
    """
    View to render forgotten password page
    """
    return render(request, "password.html")


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request):
    """
    View to verify email
    """
    token = request.GET.get('token')
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user = User.objects.get(id=payload['user_id'])
        if payload['email']:
            email = payload['email']
            user.email = email
        user.save()
        return render(request, "email.html")
    except jwt.ExpiredSignatureError:
        return render(request, "expired.html")
    except jwt.exceptions.DecodeError:
        return render(request, "invalid.html")


@api_view(['POST', 'PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def update_bio(request):
    """
    View to update bio
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    bio = request.data.get('bio', None)
    if not bio:
        return Response("bio not provided", status=status.HTTP_400_BAD_REQUEST)

    user.bio = bio
    user.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@parser_classes([MultiPartParser])
@permission_classes([IsAuthenticated])
@csrf_protect
def upload_profile_picture(request):
    """
    View to upload a profile picture
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    image = request.data.get('file', None)
    if not image:
        return Response("no image selected", status=status.HTTP_400_BAD_REQUEST)
    if not imghdr.what(image):
        return Response("not a valid image format", status=status.HTTP_400_BAD_REQUEST)

    if user.picture:
        delete_file(user.picture.path)

    user.picture = image
    user.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST', 'PUT'])
@parser_classes([MultiPartParser])
@permission_classes([IsAuthenticated])
@csrf_protect
def upload_document(request):
    """
    View to upload a document
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    file = request.data.get('file', None)
    if not file:
        return Response("no file provided", status=status.HTTP_400_BAD_REQUEST)

    tokens = os.path.splitext(str(file))
    if not tokens[1] == '.pdf':
        return Response("needs to be pdf format", status=status.HTTP_400_BAD_REQUEST)

    file_type = request.data.get('type', None)
    if not file_type:
        return Response("no type (cv/record) provided", status=status.HTTP_400_BAD_REQUEST)

    documents = Document.objects.all().filter(type=file_type)
    if documents.exists():
        document = Document.objects.get(type=file_type)
        delete_file(document.file)
        document.file = file
        document.save()
    else:
        document = Document(file=file, type=file_type)
        document.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_document(request):
    """
    View to get a document
    """
    file_type = request.GET.get('type')
    if not file_type:
        return Response("no type (cv/record) provided", status=status.HTTP_400_BAD_REQUEST)

    documents = Document.objects.all().filter(type=file_type)
    if not documents.exists():
        return Response("no " + file_type + " uploaded", status=status.HTTP_400_BAD_REQUEST)

    document = Document.objects.get(type=file_type)

    return redirect(document.file.url)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_document(request):
    """
    View to delete a document
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    file_type = request.GET.get('type')
    if not file_type:
        return Response("no type (cv/record) provided", status=status.HTTP_400_BAD_REQUEST)

    documents = Document.objects.all().filter(type=file_type)
    if documents.exists():
        document = Document.objects.get(type=file_type)
        delete_file(document.file)
        document.delete()
    else:
        return Response("document does not exist", status=status.HTTP_400_BAD_REQUEST)

    return Response(status=status.HTTP_200_OK)


@api_view(['POST', 'PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def save_address(request):
    """
    View to save address
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    street = request.data.get('street', None)
    if not street:
        return Response("street not provided", status=status.HTTP_400_BAD_REQUEST)

    suburb = request.data.get('suburb', None)
    if not suburb:
        return Response("suburb not provided", status=status.HTTP_400_BAD_REQUEST)

    city = request.data.get('city', None)
    if not city:
        return Response("city not provided", status=status.HTTP_400_BAD_REQUEST)

    postal_code = request.data.get('postal_code', None)
    if not postal_code:
        return Response("postal code not provided", status=status.HTTP_400_BAD_REQUEST)

    province = request.data.get('province', None)
    if not province:
        return Response("province not provided", status=status.HTTP_400_BAD_REQUEST)

    country = request.data.get('country', None)
    if not country:
        return Response("country not provided", status=status.HTTP_400_BAD_REQUEST)

    addresses = Address.objects.all().filter(id=1)
    if not addresses.exists():
        address = Address(street=street, suburb=suburb, city=city, postal_code=postal_code, province=province,
                          country=country)
        address.save()
    else:
        address = Address.objects.get(id=1)
        address.street = street
        address.suburb = suburb
        address.city = city
        address.postal_code = postal_code
        address.province = province
        address.country = country
        address.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def add_language(request):
    """
    View to add a programming language
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    language = request.data.get('language', None)
    if not language:
        return Response("language not provided", status=status.HTTP_400_BAD_REQUEST)

    languages = Language.objects.all().filter(language=language)

    confidence = request.data.get('confidence', None)
    if not confidence:
        return Response("confidence not provided", status=status.HTTP_400_BAD_REQUEST)

    if languages.exists():
        return Response("language already added", status=status.HTTP_400_BAD_REQUEST)

    avatar = request.data.get('avatar', None)
    if avatar:
        language = Language(language=language, confidence=confidence, avatar=avatar)
    else:
        language = Language(language=language, confidence=confidence)

    language.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def update_language(request):
    """
    View to add update programming language
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    lid = request.GET.get('id')
    if not lid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    languages = Language.objects.all().filter(id=lid)
    if not languages.exists():
        return Response("language not found", status=status.HTTP_400_BAD_REQUEST)

    language = Language.objects.get(id=lid)

    language_str = request.GET.get('language')
    if language_str:
        language.language = language_str
        language.save()

    confidence = request.data.get('confidence', None)
    if confidence:
        language.confidence = confidence
        language.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if language.avatar:
            delete_file(language.avatar)
        language.avatar = avatar
        language.save()

    return Response(status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_language(request):
    """
    View to delete a language
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    lid = request.GET.get('id')
    if not lid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    languages = Language.objects.all().filter(id=lid)
    if not languages.exists():
        return Response("language not found", status=status.HTTP_400_BAD_REQUEST)

    language = Language.objects.get(id=lid)

    if language.avatar:
        delete_file(language.avatar)

    language.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def add_framework(request):
    """
    View to add a framework
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    framework = request.data.get('framework', None)
    if not framework:
        return Response("framework not provided", status=status.HTTP_400_BAD_REQUEST)

    frameworks = Framework.objects.all().filter(framework=framework)

    confidence = request.data.get('confidence', None)
    if not confidence:
        return Response("confidence not provided", status=status.HTTP_400_BAD_REQUEST)

    if frameworks.exists():
        return Response("framework already added", status=status.HTTP_400_BAD_REQUEST)

    avatar = request.data.get('avatar', None)
    if avatar:
        framework = Framework(framework=framework, confidence=confidence, avatar=avatar)
    else:
        framework = Framework(framework=framework, confidence=confidence)

    framework.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def update_framework(request):
    """
    View to update framework
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    fid = request.GET.get('id')
    if not fid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    frameworks = Framework.objects.all().filter(id=fid)
    if not frameworks.exists():
        return Response("framework not found", status=status.HTTP_400_BAD_REQUEST)

    framework = Framework.objects.get(id=fid)

    framework_str = request.GET.get('framework')
    if framework_str:
        framework.framework = framework_str
        framework.save()

    confidence = request.data.get('confidence', None)
    if confidence:
        framework.confidence = confidence
        framework.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if framework.avatar:
            delete_file(framework.avatar)
        framework.avatar = avatar
        framework.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_framework(request):
    """
    View to delete a framework
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    fid = request.GET.get('id')
    if not fid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    frameworks = Framework.objects.all().filter(id=fid)
    if not frameworks.exists():
        return Response("framework not found", status=status.HTTP_400_BAD_REQUEST)

    framework = Framework.objects.get(id=fid)

    if framework.avatar:
        delete_file(framework.avatar)

    framework.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def add_dbms(request):
    """
    View to add a dbms
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    dbms = request.data.get('dbms', None)
    if not dbms:
        return Response("dbms not provided", status=status.HTTP_400_BAD_REQUEST)

    databases = DBMS.objects.all().filter(dbms=dbms)

    confidence = request.data.get('confidence', None)
    if not confidence:
        return Response("confidence not provided", status=status.HTTP_400_BAD_REQUEST)

    if databases.exists():
        return Response("dbms already added", status=status.HTTP_400_BAD_REQUEST)

    avatar = request.data.get('avatar', None)
    if avatar:
        dbms = DBMS(dbms=dbms, confidence=confidence, avatar=avatar)
    else:
        dbms = DBMS(dbms=dbms, confidence=confidence)

    dbms.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def update_dbms(request):
    """
    View to add update dbms
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    did = request.GET.get('id')
    if not did:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    databases = DBMS.objects.all().filter(id=did)
    if not databases.exists():
        return Response("dbms not found", status=status.HTTP_400_BAD_REQUEST)

    database = DBMS.objects.get(id=did)

    dbms = request.data.get('dbms', None)
    if dbms:
        database.dbms = dbms
        database.save()

    confidence = request.data.get('confidence', None)
    if confidence:
        database.confidence = confidence
        database.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if database.avatar:
            delete_file(database.avatar)
        database.avatar = avatar
        database.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_dbms(request):
    """
    View to delete a dbms
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    did = request.GET.get('id')
    if not did:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    databases = DBMS.objects.all().filter(id=did)
    if not databases.exists():
        return Response("dbms not found", status=status.HTTP_400_BAD_REQUEST)

    database = DBMS.objects.get(id=did)

    if database.avatar:
        delete_file(database.avatar)

    database.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def add_hobby(request):
    """
    View to add a hobby
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    hobby = request.data.get('hobby', None)
    if not hobby:
        return Response("hobby not provided", status=status.HTTP_400_BAD_REQUEST)

    hobbies = Hobby.objects.all().filter(hobby=hobby)

    if hobbies.exists():
        return Response("hobby already added", status=status.HTTP_400_BAD_REQUEST)

    avatar = request.data.get('avatar', None)
    if avatar:
        hobby = Hobby(hobby=hobby, avatar=avatar)
    else:
        hobby = Hobby(hobby=hobby)

    hobby.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def update_hobby(request):
    """
    View to update a hobby
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    hid = request.GET.get('id')
    if not hid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    hobbies = Hobby.objects.all().filter(id=hid)
    if not hobbies.exists():
        return Response("hobby not found", status=status.HTTP_400_BAD_REQUEST)

    hobby = Hobby.objects.get(id=hid)

    hobby_str = request.data.get('hobby', None)
    if hobby_str:
        hobby.hobby = hobby_str
        hobby.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if hobby.avatar:
            delete_file(hobby.avatar)
        hobby.avatar = avatar
        hobby.save()

    return Response(status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_hobby(request):
    """
    View to delete a hobby
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    hid = request.GET.get('id')
    if not hid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    hobbies = Hobby.objects.all().filter(id=hid)
    if hobbies.exists():
        hobby = Hobby.objects.get(id=hid)
        if hobby.avatar:
            delete_file(hobby.avatar)
        hobby.delete()
    else:
        return Response("hobby not found", status=status.HTTP_400_BAD_REQUEST)

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def add_skill(request):
    """
    View to add a skill
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    skill = request.data.get('skill', None)
    if not skill:
        return Response("skill not provided", status=status.HTTP_400_BAD_REQUEST)

    skills = Skill.objects.all().filter(skill=skill)

    if skills.exists():
        return Response("skill already added", status=status.HTTP_400_BAD_REQUEST)

    skill = Skill(skill=skill)
    skill.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def update_skill(request):
    """
    View to update a skill
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    sid = request.GET.get('id')
    if not sid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    skills = Skill.objects.all().filter(id=sid)

    if not skills.exists():
        return Response("skill not found", status=status.HTTP_400_BAD_REQUEST)

    skill = Skill.objects.get(id=sid)

    skill_str = request.data.get('skill', None)
    if skill_str:
        skill.skill = skill_str
        skill.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_skill(request):
    """
    View to delete a skill
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    sid = request.GET.get('id')
    if not sid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    skills = Skill.objects.all().filter(id=sid)

    if not skills.exists():
        return Response("skill not found", status=status.HTTP_400_BAD_REQUEST)

    skill = Skill.objects.get(id=sid)
    skill.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def add_work(request):
    """
    View to add work
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    description = request.data.get('description', None)
    if not description:
        return Response("description not provided", status=status.HTTP_400_BAD_REQUEST)

    company = request.data.get('company', None)
    if not company:
        return Response("company not provided", status=status.HTTP_400_BAD_REQUEST)

    jobs = Work.objects.all().filter(description=description, company=company)

    if jobs.exists():
        return Response("job already added", status=status.HTTP_400_BAD_REQUEST)

    work = Work(description=description, company=company)
    work.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def update_work(request):
    """
    View to update work
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    wid = request.GET.get('id')
    if not wid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    work = Work.objects.all().filter(id=wid)

    if not work.exists():
        return Response("work not found", status=status.HTTP_400_BAD_REQUEST)

    work = Work.objects.get(id=wid)

    description = request.data.get('description', None)
    if description:
        work.description = description
        work.save()

    company = request.data.get('company', None)
    if company:
        work.company = company
        work.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_work(request):
    """
    View to delete work
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    wid = request.GET.get('id')
    if not wid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    work = Work.objects.all().filter(id=wid)

    if not work.exists():
        return Response("work not found", status=status.HTTP_400_BAD_REQUEST)

    work = Work.objects.get(id=wid)
    work.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def add_project(request):
    """
    View to add project
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    description = request.data.get('description', None)
    if not description:
        return Response("description not provided", status=status.HTTP_400_BAD_REQUEST)

    git = request.data.get('git', None)
    if not git:
        return Response("git not provided", status=status.HTTP_400_BAD_REQUEST)

    link = request.data.get('link', None)
    if not git:
        return Response("link not provided", status=status.HTTP_400_BAD_REQUEST)

    projects = Project.objects.all().filter(description=description)

    if projects.exists():
        return Response("project already added", status=status.HTTP_400_BAD_REQUEST)

    project = Project(description=description, git=git, link=link)
    project.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def update_project(request):
    """
    View to update project
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    pid = request.GET.get('id')
    if not pid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    projects = Project.objects.all().filter(id=pid)

    if not projects.exists():
        return Response("project not found", status=status.HTTP_400_BAD_REQUEST)

    project = Project.objects.get(id=pid)

    description = request.data.get('description', None)
    if description:
        project.description = description
        project.save()

    git = request.data.get('git', None)
    if git:
        project.git = git
        project.save()

    link = request.data.get('link', None)
    if link:
        project.link = link
        project.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_project(request):
    """
    View to delete project
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    pid = request.GET.get('id')
    if not pid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    projects = Project.objects.all().filter(id=pid)

    if not projects.exists():
        return Response("project not found", status=status.HTTP_400_BAD_REQUEST)

    project = Project.objects.get(id=pid)
    project.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def add_eduction(request):
    """
    View to add education
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    degree = request.data.get('degree', None)
    if not degree:
        return Response("degree not provided", status=status.HTTP_400_BAD_REQUEST)

    grade = request.data.get('grade', None)

    year = request.data.get('year', None)
    if not year:
        return Response("year not provided", status=status.HTTP_400_BAD_REQUEST)

    institution = request.data.get('institution', None)
    if not institution:
        return Response("institution not provided", status=status.HTTP_400_BAD_REQUEST)

    degrees = Education.objects.all().filter(degree=degree)

    if degrees.exists():
        return Response("degree already added", status=status.HTTP_400_BAD_REQUEST)

    if grade:
        degree = Education(degree=degree, grade=grade, year=year, institution=institution)
        degree.save()
    else:
        degree = Education(degree=degree, year=year, institution=institution)
        degree.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
@csrf_protect
def update_education(request):
    """
    View to update education
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    eid = request.GET.get('id')
    if not eid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    degrees = Education.objects.all().filter(id=eid)

    if not degrees.exists():
        return Response("degree not found", status=status.HTTP_400_BAD_REQUEST)

    education = Education.objects.get(id=eid)

    degree = request.data.get('degree', None)
    if degree:
        education.degree = degree
        education.save()

    grade = request.data.get('grade', None)
    if grade:
        education.grade = grade
        education.save()

    year = request.data.get('year', None)
    if year:
        education.year = year
        education.save()

    institution = request.data.get('institution', None)
    if institution:
        education.institution = institution
        education.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_eduction(request):
    """
    View to delete eduction
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    eid = request.GET.get('id')
    if not eid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    degrees = Education.objects.all().filter(id=eid)

    if not degrees.exists():
        return Response("degree not found", status=status.HTTP_400_BAD_REQUEST)

    education = Education.objects.get(id=eid)
    education.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_protect
def refresh_token_view(request):
    """
    View to refresh access token
    To obtain a new access_token this view expects 2 important things:
        1. a cookie that contains a valid refresh_token
        2. a header 'X-CSRFTOKEN' with a valid csrf token, client app can get it from cookies "csrftoken"
    """
    refresh_token = request.COOKIES.get('refresh_token')
    if refresh_token is None:
        raise exceptions.AuthenticationFailed(
            'authentication credentials were not provided.')
    try:
        payload = jwt.decode(
            refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed(
            'expired refresh token, please login again.')

    user = User.objects.filter(id=payload.get('user_id')).first()
    if user is None:
        raise exceptions.AuthenticationFailed('User not found')

    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    user.token_last_expired = timezone.now()
    user.security_code = generate_security_code()
    user.authenticated = False
    user.save()

    email_2fa(user)

    token = generate_access_token(user, False)
    return Response({'token': token})