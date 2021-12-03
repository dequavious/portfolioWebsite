import imghdr
import re

from django.contrib.auth.hashers import check_password, make_password
from django.http import HttpResponse
from django.template import RequestContext
from django.template.loader import render_to_string
from rest_framework import status, exceptions
from rest_framework.decorators import api_view, permission_classes, parser_classes, authentication_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect

from django.contrib import messages

from .serializers import *
from .utils import *
from .models import CustomUser as User, Document, Language, Hobby, Skill, Address, Framework, DBMS


def home(request):
    user = User.objects.get(id=1)
    user = UserSerializer(user, many=False)
    lang = Language.objects.all()
    lang = LanguageSerializer(lang, many=True)
    technologies = Framework.objects.all()
    technologies = FrameworkSerializer(technologies, many=True)
    db = DBMS.objects.all()
    db = DBMSSerializer(db, many=True)
    interests = Hobby.objects.all()
    interests = HobbySerializer(interests, many=True)
    skills = Skill.objects.all()
    skills = SkillSerializer(skills, many=True)

    jobs = Work.objects.all()
    jobs = WorkSerializer(jobs, many=True)

    proj = Project.objects.all()
    proj = ProjectSerializer(proj, many=True)

    degrees = Education.objects.all()
    degrees = EducationSerializer(degrees, many=True)

    context = {'user': user.data, 'languages': lang.data, 'frameworks': technologies.data,
               'databases': db.data, 'hobbies': interests.data, 'skills': skills.data, 'jobs': jobs.data,
               'projects': proj.data, 'degrees': degrees.data}
    return render(request, 'portfolio/home.html', context)


def login_page(request):
    # try:
    #     if request.session['alert']:
    #         context = {
    #             'alert': request.session['alert']
    #         }
    #         request.session.pop('alert')
    #         return render(request, 'admin/login.html', context)
    # except:
    #     return render(request, 'admin/login.html')
    return render(request, 'admin/login.html')


@permission_classes([IsAuthenticated])
def auth_page(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')

    # user = UserSerializer(user, many=False)
    context = {
        'auth': user.authenticated,
        'token': request.session['token']
    }
    return render(request, 'admin/auth.html', context)


def admin(request):
    return redirect('details')


@permission_classes([IsAuthenticated])
def password_page(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    user = UserSerializer(user, many=False)

    context = {
        'user': user.data,
        'token': request.session['token'],
    }

    return render(request, 'admin/password.html', context)


@permission_classes([AllowAny])
def forgot_password_page(request):

    context = {
        'token': request.session['token'],
    }

    return render(request, 'admin/forgot_password.html', context)


@permission_classes([IsAuthenticated])
def details(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    user = UserSerializer(user, many=False)

    context = {
        'token': request.session['token'],
        'user': user.data,
    }

    return render(request, 'admin/details.html', context)


@permission_classes([IsAuthenticated])
def documents(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    docs = Document.objects.all()
    docs = DocumentSerializer(docs, many=True)

    context = {
        'token': request.session['token'],
        'documents': docs.data,
    }

    return render(request, 'admin/documents.html', context)


@permission_classes([IsAuthenticated])
def hobbies(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    interests = Hobby.objects.all()
    interests = HobbySerializer(interests, many=True)

    context = {
        'token': request.session['token'],
        'hobbies': interests.data,
    }

    return render(request, 'admin/hobbies.html', context)


@permission_classes([IsAuthenticated])
def education(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    edu = Education.objects.all()
    edu = EducationSerializer(edu, many=True)

    context = {
        'token': request.session['token'],
        'degrees': edu.data,
    }

    return render(request, 'admin/education.html', context)


@permission_classes([IsAuthenticated])
def work(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    jobs = Work.objects.all()
    jobs = WorkSerializer(jobs, many=True)

    context = {
        'token': request.session['token'],
        'jobs': jobs.data,
    }

    return render(request, 'admin/work.html', context)


@permission_classes([IsAuthenticated])
def strengths(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    skills = Skill.objects.all()
    skills = SkillSerializer(skills, many=True)

    context = {
        'token': request.session['token'],
        'skills': skills.data,
    }

    return render(request, 'admin/strengths.html', context)


@permission_classes([IsAuthenticated])
def projects(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    proj = Project.objects.all()
    proj = ProjectSerializer(proj, many=True)

    context = {
        'token': request.session['token'],
        'projects': proj.data,
    }

    return render(request, 'admin/projects.html', context)


@permission_classes([IsAuthenticated])
def languages(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    lang = Language.objects.all()
    lang = LanguageSerializer(lang, many=True)

    context = {
        'token': request.session['token'],
        'languages': lang.data,
    }

    return render(request, 'admin/languages.html', context)


@permission_classes([IsAuthenticated])
def frameworks(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    technologies = Framework.objects.all()
    technologies = FrameworkSerializer(technologies, many=True)

    context = {
        'token': request.session['token'],
        'frameworks': technologies.data,
    }

    return render(request, 'admin/frameworks.html', context)


@permission_classes([IsAuthenticated])
def databases(request):
    user_id = request.session.get('user', None)
    if not user_id:
        return redirect('login page')

    users = User.objects.all().filter(id=user_id)
    if not users.exists():
        return redirect('login page')
    user = User.objects.get(id=user_id)
    if not user.is_active:
        return redirect('login page')
    if not user.authenticated:
        return redirect('login page')

    db = DBMS.objects.all()
    db = DBMSSerializer(db, many=True)

    context = {
        'token': request.session['token'],
        'databases': db.data,
    }

    return render(request, 'admin/databases.html', context)


@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login(request):
    """
    View to log in
    """
    if not request.data.get('email', None):
        messages.error(request, "Email not provided")
        return render(request, 'admin/login.html')

    if not request.data.get('password', None):
        messages.error(request, "Password not provided")
        return render(request, 'admin/login.html')

    users = User.objects.all().filter(email=request.data['email'])
    if not users.exists():
        messages.error(request, "Email does not exist")
        return render(request, 'admin/login.html')
    user = User.objects.get(email=request.data['email'])
    if not check_password(request.data['password'], user.password):
        messages.error(request, "Incorrect password")
        return render(request, 'admin/login.html')

    user.token_last_expired = timezone.now()
    user.authenticated = False
    user.security_code = generate_security_code()
    user.is_active = True
    user.save()

    request.user = user

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

    request.session['user'] = user.id
    request.session['token'] = access_token

    email_2fa(user)

    return redirect('auth page')


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

    security_code = request.data.get('security_code', None)
    if not security_code:
        messages.error(request, "No security code provided")
        return render(request, 'admin/auth.html')

    if security_code != user.security_code:
        messages.error(request, "Incorrect code")
        html = render_to_string('admin/auth.html')
        return HttpResponse(html)
    user.authenticated = True
    user.security_code = None
    user.save()

    return Response(status=status.HTTP_200_OK)


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


@api_view(['POST'])
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

    name = request.data.get('name', None)
    if name:
        user.name = name
        user.save()

    surname = request.data.get('surname', None)
    if surname:
        user.surname = surname
        user.save()

    number = request.data.get('number', None)
    if number:
        user.number = number
        user.save()

    bio = request.data.get('bio', None)
    if bio:
        user.bio = bio
        user.save()

    image = request.data.get('file', None)
    if image:
        if not imghdr.what(image):
            messages.error(request, "Not a valid image format")
            html = render_to_string('admin/details.html')
            return HttpResponse(html)

        if user.picture:
            delete_file(user.picture)

        user.picture = image
        user.save()

    email = request.data.get('email', None)
    if email:
        if User.objects.all().filter(email=email).exists():
            messages.error(request, "Email already exists.")
            html = render_to_string('admin/details.html')
            return HttpResponse(html)
        temp = User(id=user.id, email=email, name=user.name, surname=user.surname,
                    number=user.number, password=user.password)
        send_email_verification_link(temp, request)

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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
        messages.error(request, "Incorrect password")
        html = render_to_string('admin/password.html')
        return HttpResponse(html)

    if not re.search("^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W).{12,}$", request.data['new_password']):
        messages.error(request, "Invalid password")
        html = render_to_string('admin/password.html')
        return HttpResponse(html)

    if request.data['new_password'] != request.data['repeat_password']:
        messages.error(request, "Passwords don't match")
        html = render_to_string('admin/password.html')
        return HttpResponse(html)

    user.password = make_password(request.data['new_password'])
    user.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['GET'])
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

        return redirect('password page')
    else:
        return Response("no email provided", status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
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
            messages.error(request, "Invalid password")
            html = render_to_string('admin/forgot_password.html')
            return HttpResponse(html)

        if request.data['password'] != request.data['repeat_password']:
            messages.error(request, "Passwords don't match")
            html = render_to_string('admin/forgot_password.html')
            return HttpResponse(html)

        user.password = make_password(request.data['password'])
        user.save()

        return Response(status=status.HTTP_200_OK)
    except jwt.ExpiredSignatureError:
        return Response("Token expired", status=status.HTTP_400_BAD_REQUEST)
    except jwt.exceptions.DecodeError:
        return Response("Invalid token", status=status.HTTP_400_BAD_REQUEST)


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
        return redirect('details')
    except jwt.ExpiredSignatureError:
        return Response("Token expired", status=status.HTTP_400_BAD_REQUEST)
    except jwt.exceptions.DecodeError:
        return Response("Invalid token", status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
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
        messages.error(request, "Needs to be pdf format")
        html = render_to_string('admin/documents.html')
        return HttpResponse(html)

    file_type = request.data.get('type', None)
    if not file_type:
        return Response("no type (cv/record) provided", status=status.HTTP_400_BAD_REQUEST)

    if not ((file_type == "cv") or (file_type == "record")):
        return Response("invalid type", status=status.HTTP_400_BAD_REQUEST)

    docs = Document.objects.all().filter(type=file_type)
    if docs.exists():
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


@api_view(['POST'])
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

    docs = Document.objects.all().filter(type=file_type)
    if docs.exists():
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

    confidence = request.data.get('confidence', None)
    if not confidence:
        return Response("confidence not provided", status=status.HTTP_400_BAD_REQUEST)

    lang = Language.objects.all().filter(language__iexact=language)

    if lang.exists():
        request.session['alert'] = "Language already added"
        return redirect('languages')
        # return Response("language already added", status=status.HTTP_400_BAD_REQUEST)

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            request.session['alert'] = "Not a valid image format"
            return redirect('languages')
        language = Language(language=language, confidence=confidence, avatar=avatar)
    else:
        language = Language(language=language, confidence=confidence)

    language.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    lang = Language.objects.all().filter(id=lid)
    if not lang.exists():
        return Response("language not found", status=status.HTTP_400_BAD_REQUEST)

    language = Language.objects.get(id=lid)

    language_str = request.data.get('language', None)
    if language_str:
        lang = Language.objects.all().filter(language__iexact=language_str)

        if lang.exists():
            request.session['alert'] = "Language already added"
            return redirect('languages')
        language.language = language_str
        language.save()

    confidence = request.data.get('confidence', None)
    if confidence:
        language.confidence = confidence
        language.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            request.session['alert'] = "Not a valid image format"
            return redirect('languages')
        if language.avatar:
            delete_file(language.avatar)
        language.avatar = avatar
        language.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    lang = Language.objects.all().filter(id=lid)
    if not lang.exists():
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

    confidence = request.data.get('confidence', None)
    if not confidence:
        return Response("confidence not provided", status=status.HTTP_400_BAD_REQUEST)

    technologies = Framework.objects.all().filter(framework__iexact=framework)

    if technologies.exists():
        request.session['alert'] = "Framework already added"
        return redirect('frameworks')

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            request.session['alert'] = "Not a valid image format"
            return redirect('frameworks')
        framework = Framework(framework=framework, confidence=confidence, avatar=avatar)
    else:
        framework = Framework(framework=framework, confidence=confidence)

    framework.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    technologies = Framework.objects.all().filter(id=fid)
    if not technologies.exists():
        return Response("framework not found", status=status.HTTP_400_BAD_REQUEST)

    framework = Framework.objects.get(id=fid)

    framework_str = request.data.get('framework', None)
    if framework_str:
        technologies = Framework.objects.all().filter(framework__iexact=framework_str)

        if technologies.exists():
            request.session['alert'] = "Framework already added"
            return redirect('frameworks')
        framework.framework = framework_str
        framework.save()

    confidence = request.data.get('confidence', None)
    if confidence:
        framework.confidence = confidence
        framework.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            request.session['alert'] = "Not a valid image format"
            return redirect('frameworks')
        if framework.avatar:
            delete_file(framework.avatar)
        framework.avatar = avatar
        framework.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    technologies = Framework.objects.all().filter(id=fid)
    if not technologies.exists():
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

    confidence = request.data.get('confidence', None)
    if not confidence:
        return Response("confidence not provided", status=status.HTTP_400_BAD_REQUEST)

    db = DBMS.objects.all().filter(dbms__iexact=dbms)
    if db.exists():
        request.session['alert'] = "Database already added"
        return redirect('databases')

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            request.session['alert'] = "Not a valid image format"
            return redirect('databases')
        dbms = DBMS(dbms=dbms, confidence=confidence, avatar=avatar)
    else:
        dbms = DBMS(dbms=dbms, confidence=confidence)

    dbms.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    db = DBMS.objects.all().filter(id=did)
    if not db.exists():
        return Response("dbms not found", status=status.HTTP_400_BAD_REQUEST)

    database = DBMS.objects.get(id=did)

    dbms = request.data.get('dbms', None)
    if dbms:
        db = DBMS.objects.all().filter(dbms__iexact=dbms)
        if db.exists():
            request.session['alert'] = "Database already added"
            return redirect('databases')
        database.dbms = dbms
        database.save()

    confidence = request.data.get('confidence', None)
    if confidence:
        database.confidence = confidence
        database.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            request.session['alert'] = "Not a valid image format"
            return redirect('databases')
        if database.avatar:
            delete_file(database.avatar)
        database.avatar = avatar
        database.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    db = DBMS.objects.all().filter(id=did)
    if not db.exists():
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

    interests = Hobby.objects.all().filter(hobby__iexact=hobby)
    if interests.exists():
        messages.error(request, "Hobby already added")
        html = render_to_string('admin/hobbies.html')
        return HttpResponse(html)

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            messages.error(request, "Not a valid image format")
            html = render_to_string('admin/hobbies.html')
            return HttpResponse(html)
        hobby = Hobby(hobby=hobby, avatar=avatar)
    else:
        hobby = Hobby(hobby=hobby)

    hobby.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    interests = Hobby.objects.all().filter(id=hid)
    if not interests.exists():
        return Response("hobby not found", status=status.HTTP_400_BAD_REQUEST)

    hobby = Hobby.objects.get(id=hid)

    interest = request.data.get('hobby', None)
    if interest:
        interests = Hobby.objects.all().filter(hobby__iexact=interest)
        if interests.exists():
            messages.error(request, "Hobby already added")
            html = render_to_string('admin/hobbies.html')
            return HttpResponse(html)
        hobby.hobby = interest
        hobby.save()

    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            messages.error(request, "Not a valid image format")
            html = render_to_string('admin/hobbies.html')
            return HttpResponse(html)
        if hobby.avatar:
            delete_file(hobby.avatar)
        hobby.avatar = avatar
        hobby.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    interests = Hobby.objects.all().filter(id=hid)
    if interests.exists():
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

    skills = Skill.objects.all().filter(skill__iexact=skill)

    if skills.exists():
        messages.error(request, "Strength already added")
        html = render_to_string('admin/strengths.html')
        return HttpResponse(html)

    skill = Skill(skill=skill)
    skill.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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
        skills = Skill.objects.all().filter(skill__iexact=skill_str)
        if skills.exists():
            messages.error(request, "Strength already added")
            html = render_to_string('admin/strengths.html')
            return HttpResponse(html)
        skill.skill = skill_str
        skill.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    jobs = Work.objects.all().filter(description__iexact=description, company__iexact=company)

    if jobs.exists():
        messages.error(request, "Work already added")
        html = render_to_string('admin/work.html')
        return HttpResponse(html)

    job = Work(description=description, company=company)
    job.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    jobs = Work.objects.all().filter(id=wid)

    if not jobs.exists():
        return Response("work not found", status=status.HTTP_400_BAD_REQUEST)

    job = Work.objects.get(id=wid)

    description = request.data.get('description', None)
    company = request.data.get('company', None)

    if description and company:
        jobs = Work.objects.all().filter(description__iexact=description, company__iexact=company)
        if jobs.exists():
            messages.error(request, "Work already added")
            html = render_to_string('admin/work.html')
            return HttpResponse(html)

    if description:
        job.description = description
        job.save()

    if company:
        job.company = company
        job.save()

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

    job = Work.objects.all().filter(id=wid)

    if not job.exists():
        return Response("work not found", status=status.HTTP_400_BAD_REQUEST)

    job = Work.objects.get(id=wid)
    job.delete()

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

    title = request.data.get('title', None)
    if not title:
        return Response("title not provided", status=status.HTTP_400_BAD_REQUEST)

    description = request.data.get('description', None)
    if not description:
        return Response("description not provided", status=status.HTTP_400_BAD_REQUEST)

    git = request.data.get('git', None)
    if not git:
        return Response("git not provided", status=status.HTTP_400_BAD_REQUEST)

    link = request.data.get('link', None)
    if not git:
        return Response("link not provided", status=status.HTTP_400_BAD_REQUEST)

    proj = Project.objects.all().filter(title__iexact=title)

    if proj.exists():
        messages.error(request, "Project already added")
        html = render_to_string('admin/strengths.html')
        return HttpResponse(html)

    project = Project(title=title, description=description, git=git, link=link)
    project.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    proj = Project.objects.all().filter(id=pid)

    if not proj.exists():
        return Response("project not found", status=status.HTTP_400_BAD_REQUEST)

    project = Project.objects.get(id=pid)

    title = request.data.get('title', None)
    if title:
        proj = Project.objects.all().filter(title__iexact=title)

        if proj.exists():
            messages.error(request, "Project already added")
            html = render_to_string('admin/strengths.html')
            return HttpResponse(html)

        project.title = title
        project.save()

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


@api_view(['POST'])
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

    proj = Project.objects.all().filter(id=pid)

    if not proj.exists():
        return Response("project not found", status=status.HTTP_400_BAD_REQUEST)

    project = Project.objects.get(id=pid)
    project.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def add_education(request):
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

    degrees = Education.objects.all().filter(degree__iexact=degree)

    if degrees.exists():
        messages.error(request, "Degree already added")
        html = render_to_string('admin/education.html')
        return HttpResponse(html)

    if grade:
        degree = Education(degree=degree, grade=grade, year=year, institution=institution)
        degree.save()
    else:
        degree = Education(degree=degree, year=year, institution=institution)
        degree.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
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

    degree = Education.objects.get(id=eid)

    degree_str = request.data.get('degree', None)
    if degree_str:
        degrees = Education.objects.all().filter(degree__iexact=degree_str)
        if degrees.exists():
            messages.error(request, "Degree already added")
            html = render_to_string('admin/education.html')
            return HttpResponse(html)
        degree.degree = degree_str
        degree.save()

    grade = request.data.get('grade', None)
    if grade:
        degree.grade = grade
        degree.save()

    year = request.data.get('year', None)
    if year:
        degree.year = year
        degree.save()

    institution = request.data.get('institution', None)
    if institution:
        degree.institution = institution
        degree.save()

    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_education(request):
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

    degree = Education.objects.get(id=eid)
    degree.delete()

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

    if not user.is_active:
        return Response("User inactive", status=status.HTTP_400_BAD_REQUEST)

    if not user.authenticated:
        return Response("User not authenticated", status=status.HTTP_400_BAD_REQUEST)

    user.token_last_expired = timezone.now()
    user.security_code = generate_security_code()
    user.authenticated = False
    user.save()

    email_2fa(user)

    token = generate_access_token(user, False)
    return Response({'token': token})
