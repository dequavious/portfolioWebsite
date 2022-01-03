import imghdr
import json
import re

from django.contrib.auth.hashers import check_password, make_password
from django.http import HttpResponse
from django.template.loader import render_to_string
from rest_framework import status, exceptions
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect

from django.contrib import messages

from .serializers import *
from .utils import *
from .models import CustomUser as User, Document, Hobby, Skill, Address, Technology, Project, ProjectStack, Quote, \
    Education


def home(request):
    user = User.objects.get(id=1)
    user = UserSerializer(user, many=False)

    techs = Technology.objects.all().order_by('type')
    techs = TechnologySerializer(techs, many=True)

    langs = Technology.objects.all().filter(type='Language')
    langs = TechnologySerializer(langs, many=True)

    fworks = Technology.objects.all().filter(type='Framework')
    fworks = TechnologySerializer(fworks, many=True)

    db = Technology.objects.all().filter(type='Database')
    db = TechnologySerializer(db, many=True)

    tool_list = Technology.objects.all().filter(type='Tool')
    tool_serializer = TechnologySerializer(tool_list, many=True)

    interests = Hobby.objects.all()
    interests = HobbySerializer(interests, many=True)

    skills = Skill.objects.all()
    skills = SkillSerializer(skills, many=True)

    jobs = Work.objects.all()
    jobs = WorkSerializer(jobs, many=True)

    proj = Project.objects.all()
    proj = ProjectSerializer(proj, many=True)

    stack = ProjectStack.objects.all()
    stack = ProjectStackSerializer(stack, many=True)

    degrees = Education.objects.all()
    degrees = EducationSerializer(degrees, many=True)

    quotes = Quote.objects.all().filter(id=1)
    if quotes:
        quote = quotes.first()
        quote = QuoteSerializer(quote, many=False)
        context = {'user': user.data, 'languages': langs.data, 'frameworks': fworks.data,
                   'databases': db.data, 'tools': tool_serializer.data, 'techs': techs.data, 'hobbies': interests.data,
                   'skills': skills.data, 'jobs': jobs.data, 'projects': proj.data, 'stack': stack.data,
                   'degrees': degrees.data, 'quote': quote.data}
    else:
        context = {'user': user.data, 'languages': langs.data, 'frameworks': fworks.data,
                   'databases': db.data, 'tools': tool_serializer.data, 'techs': techs.data, 'hobbies': interests.data,
                   'skills': skills.data, 'jobs': jobs.data, 'projects': proj.data, 'stack': stack.data,
                   'degrees': degrees.data}

    return render(request, 'portfolio/index.html', context)


@api_view(['POST'])
@permission_classes([AllowAny])
def send_message(request):
    """
    View to send an email
    """

    email = request.data.get('email')
    name = request.data.get('name')
    subject = request.data.get('subject')
    body = request.data.get('body')

    if (email is not None) and (name is not None) and (body is not None) and (subject is not None):

        user = User.objects.get(id=1)

        data = {
            'subject': subject,
            'body': '''{}
            
                    From:
                    {}
                    {}
                    '''.format(body, name, email),
            'to_address': [user.email],
        }

        send_email(data)

        return redirect('home')

    else:

        return Response("name/email/subject/body missing", status=status.HTTP_400_BAD_REQUEST)


def login_page(request):
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
    quotes = Quote.objects.all().filter(id=1)
    if quotes:
        quote = quotes.first()
        quote = QuoteSerializer(quote, many=False)
        context = {
            'token': request.session['token'],
            'user': user.data,
            'quote': quote.data,
        }
    else:
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

    stack = ProjectStack.objects.all()
    stack = ProjectStackSerializer(stack, many=True)

    techs = Technology.objects.all()
    techs = TechnologySerializer(techs, many=True)

    context = {
        'token': request.session['token'],
        'projects': proj.data,
        'stack': stack.data,
        'techs': techs.data,
    }

    return render(request, 'admin/projects.html', context)


@permission_classes([IsAuthenticated])
def technologies(request):
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

    techs = Technology.objects.all()
    techs = TechnologySerializer(techs, many=True)

    context = {
        'token': request.session['token'],
        'techs': techs.data,
    }

    return render(request, 'admin/technologies.html', context)

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

    messages.info(request, "Please enter the security code that has been sent to your email.")
    return redirect('auth page')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def two_factor_auth(request):
    """
    View to send 2-factor authentication security code
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
    View to authenticate user using 2-factor authentication
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

    just_email = True

    name = request.data.get('name', None)
    if name:
        user.name = name
        user.save()
        just_email = False

    surname = request.data.get('surname', None)
    if surname:
        user.surname = surname
        user.save()
        just_email = False

    number = request.data.get('number', None)
    if number:
        user.number = number
        user.save()
        just_email = False

    bio = request.data.get('bio', None)
    if bio:
        user.bio = bio
        user.save()
        just_email = False

    quote = request.data.get('quote', None)
    if quote:
        author = request.data.get('author', None)
        if not author:
            messages.error(request, "Please provide an author for the quote.")
            html = render_to_string('admin/details.html')
            return HttpResponse(html)
        old = Quote.objects.all().filter(id=1)
        if old.exists():
            old = old.first()
            old.quote = quote
            old.author = author
        else:
            new_quote = Quote(quote=quote, author=author)
            new_quote.save()
        just_email = False

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
        just_email = False

    email = request.data.get('email', None)
    if email:
        if User.objects.all().filter(email=email).exists():
            messages.error(request, "Email already exists.")
            html = render_to_string('admin/details.html')
            return HttpResponse(html)
        temp = User(id=user.id, email=email, name=user.name, surname=user.surname,
                    number=user.number, password=user.password)
        send_email_verification_link(temp, request)
        messages.info(request, "A link has been sent to verify your new email.")

    if not just_email:
        messages.success(request, "Details updated successfully.")
    html = render_to_string('admin/details.html')
    return HttpResponse(html)


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

    messages.success(request, "Password has been reset.")
    html = render_to_string('admin/password.html')
    return HttpResponse(html)


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

        messages.info(request, "A link has been sent to your email to change your password.")
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

        messages.success(request, "Password has been reset.")
        html = render_to_string('admin/forgot_password.html')
        return HttpResponse(html)
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
        messages.success(request, "Email verification successful.")
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
        return Response("no type provided", status=status.HTTP_400_BAD_REQUEST)

    if not ((file_type == "cv") or (file_type == "bachelor") or (file_type == "honours") or (file_type == "record")):
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

    messages.success(request, "Document upload successful.")
    html = render_to_string('admin/documents.html')
    return HttpResponse(html)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_document(request):
    """
    View to get a document
    """
    file_type = request.GET.get('type')
    if not file_type:
        return Response("no type provided", status=status.HTTP_400_BAD_REQUEST)

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
        return Response("no type provided", status=status.HTTP_400_BAD_REQUEST)

    docs = Document.objects.all().filter(type=file_type)
    if docs.exists():
        document = Document.objects.get(type=file_type)
        delete_file(document.file)
        document.delete()
    else:
        return Response("document does not exist", status=status.HTTP_400_BAD_REQUEST)

    messages.success(request, "Document has been deleted.")
    html = render_to_string('admin/documents.html')
    return HttpResponse(html)


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
def add_technology(request):
    """
    View to add a technology
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    name = request.data.get('name', None)
    if not name:
        return Response("name not provided", status=status.HTTP_400_BAD_REQUEST)

    type = request.data.get('type', None)
    if not type:
        return Response("type not provided", status=status.HTTP_400_BAD_REQUEST)


    confidence = request.data.get('confidence', None)
    if not confidence:
        return Response("confidence not provided", status=status.HTTP_400_BAD_REQUEST)


    avatar = request.data.get('avatar', None)
    if not avatar:
        return Response("avatar not provided", status=status.HTTP_400_BAD_REQUEST)

    techs = Technology.objects.all().filter(name__iexact=name)

    if techs.exists():
        messages.error(request, "Technology already added")
        html = render_to_string('admin/technologies.html')
        return HttpResponse(html)

    if not imghdr.what(avatar):
        messages.error(request, "Not a valid image format")
        html = render_to_string('admin/technologies.html')
        return HttpResponse(html)
    tech = Technology(name=name, type=type, confidence=confidence, avatar=avatar)
    tech.save()

    messages.success(request, "Technology has been added.")
    html = render_to_string('admin/technologies.html')
    return HttpResponse(html)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
@csrf_protect
def update_technology(request):
    """
    View to update a technology
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    tid = request.GET.get('id')
    if not tid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    techs = Technology.objects.all().filter(id=tid)
    if not techs.exists():
        return Response("technology not found", status=status.HTTP_400_BAD_REQUEST)

    tech = Technology.objects.get(id=tid)

    name = request.data.get('name', None)
    if name:
        techs = Technology.objects.all().filter(name__iexact=name)

        if techs.exists() and (int(techs.first().id) != int(tid)):
            messages.error(request, "Technology already exists")
            html = render_to_string('admin/technologies.html')
            return HttpResponse(html)
        tech.name = name
        tech.save()


    type = request.data.get('type', None)
    if type:
        tech.type = type
        tech.save()


    confidence = request.data.get('confidence', None)
    if confidence:
        tech.confidence = confidence
        tech.save()


    avatar = request.data.get('avatar', None)
    if avatar:
        if not imghdr.what(avatar):
            messages.error(request, "Not a valid image format")
            html = render_to_string('admin/technologies.html')
            return HttpResponse(html)
        if tech.avatar:
            delete_file(tech.avatar)
        tech.avatar = avatar
        tech.save()

    messages.success(request, "Technology has been updated.")
    html = render_to_string('admin/technologies.html')
    return HttpResponse(html)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@csrf_protect
def delete_technology(request):
    """
    View to delete a technology
    """
    users = User.objects.all().filter(id=request.user.id)
    if not users.exists():
        return Response("user does not exist", status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.get(id=request.user.id)
    if not user.authenticated:
        return Response("account not authenticated", status=status.HTTP_400_BAD_REQUEST)

    tid = request.GET.get('id')
    if not tid:
        return Response("id not provided", status=status.HTTP_400_BAD_REQUEST)

    techs = Technology.objects.all().filter(id=tid)
    if not techs.exists():
        return Response("technology not found", status=status.HTTP_400_BAD_REQUEST)

    tech = Technology.objects.get(id=tid)

    if tech.avatar:
        delete_file(tech.avatar)

    tech.delete()

    messages.success(request, "Technology has been deleted.")
    html = render_to_string('admin/technologies.html')
    return HttpResponse(html)


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

    messages.success(request, "Hobby has been added.")
    html = render_to_string('admin/hobbies.html')
    return HttpResponse(html)


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
        if interests.exists() and (int(interests.first().id) != int(hid)):
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

    messages.success(request, "Hobby has been updated.")
    html = render_to_string('admin/hobbies.html')
    return HttpResponse(html)


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

    messages.success(request, "Hobby has been deleted.")
    html = render_to_string('admin/hobbies.html')
    return HttpResponse(html)


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

    messages.success(request, "Strength has been added.")
    html = render_to_string('admin/strengths.html')
    return HttpResponse(html)


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
        if skills.exists() and (int(skills.first().id) != int(sid)):
            messages.error(request, "Strength already added")
            html = render_to_string('admin/strengths.html')
            return HttpResponse(html)
        skill.skill = skill_str
        skill.save()

    messages.success(request, "Strength has been updated.")
    html = render_to_string('admin/strengths.html')
    return HttpResponse(html)


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

    messages.success(request, "Strength has been deleted.")
    html = render_to_string('admin/strengths.html')
    return HttpResponse(html)


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

    messages.success(request, "Work has been added.")
    html = render_to_string('admin/work.html')
    return HttpResponse(html)


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
        if jobs.exists() and (int(jobs.first().id) != int(wid)):
            messages.error(request, "Work already added")
            html = render_to_string('admin/work.html')
            return HttpResponse(html)

    if description:
        jobs = Work.objects.all().filter(description__iexact=description, company__iexact=job.company)
        if jobs.exists() and (int(jobs.first().id) != int(wid)):
            messages.error(request, "Work already added")
            html = render_to_string('admin/work.html')
            return HttpResponse(html)
        job.description = description
        job.save()

    if company:
        jobs = Work.objects.all().filter(description__iexact=job.description, company__iexact=company)
        if jobs.exists() and (int(jobs.first().id) != int(wid)):
            messages.error(request, "Work already added")
            html = render_to_string('admin/work.html')
            return HttpResponse(html)
        job.company = company
        job.save()

    messages.success(request, "Work has been updated.")
    html = render_to_string('admin/work.html')
    return HttpResponse(html)


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

    messages.success(request, "Work has been deleted.")
    html = render_to_string('admin/work.html')
    return HttpResponse(html)


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

    link = request.data.get('link', None)

    proj = Project.objects.all().filter(title__iexact=title)

    if proj.exists():
        messages.error(request, "Project already added")
        html = render_to_string('admin/strengths.html')
        return HttpResponse(html)

    if git and link:
        project = Project(title=title, description=description, git=git, link=link)
        project.save()
    elif git:
        project = Project(title=title, description=description, git=git)
        project.save()
    elif link:
        project = Project(title=title, description=description, link=link)
        project.save()
    else:
        project = Project(title=title, description=description)
        project.save()

    stack = request.data.get('stack', None)
    if stack:
        stack = json.loads(stack)
        for tech in stack:
            techs = Technology.objects.all().filter(name=tech.get('technology'))
            if not techs.exists():
                return Response("technology not found", status=status.HTTP_400_BAD_REQUEST)
            technology = techs.first()
            new_entry = ProjectStack(project=project, technology=technology)
            new_entry.save()

    messages.success(request, "Project has been added.")
    html = render_to_string('admin/projects.html')
    return HttpResponse(html)


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

        if proj.exists() and (int(proj.first().id) != int(pid)):
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

    stack = request.data.get('stack', None)
    if stack:
        old = ProjectStack.objects.all().filter(project=project)
        old.delete()
        stack = json.loads(stack)
        for tech in stack:
            techs = Technology.objects.all().filter(name=tech.get('technology'))
            if not techs.exists():
                return Response("technology not found", status=status.HTTP_400_BAD_REQUEST)
            technology = techs.first()
            new_entry = ProjectStack(project=project, technology=technology)
            new_entry.save()

    messages.success(request, "Project has been updated.")
    html = render_to_string('admin/projects.html')
    return HttpResponse(html)


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

    messages.success(request, "Project has been deleted.")
    html = render_to_string('admin/projects.html')
    return HttpResponse(html)


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

    messages.success(request, "Degree has been added.")
    html = render_to_string('admin/education.html')
    return HttpResponse(html)


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
        if degrees.exists() and (int(degrees.first().id) != int(eid)):
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

    messages.success(request, "Degree has been updated.")
    html = render_to_string('admin/education.html')
    return HttpResponse(html)


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

    messages.success(request, "Degree has been deleted.")
    html = render_to_string('admin/education.html')
    return HttpResponse(html)


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
