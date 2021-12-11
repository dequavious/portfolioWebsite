import math
import os
import random

import jwt
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone


def generate_access_token(user, remember_me):
    if remember_me:
        token_payload = {
            'user_id': user.id,
            'exp': timezone.now() + timezone.timedelta(days=7),
            'iat': timezone.now(),
        }
    else:
        token_payload = {
            'user_id': user.id,
            'exp': timezone.now() + timezone.timedelta(minutes=15),
            'iat': timezone.now(),
        }
    token = jwt.encode(token_payload, settings.SECRET_KEY, algorithm='HS256')
    return token


def generate_refresh_token(user, email_verification, forgot_password):
    if email_verification:
        refresh_token_payload = {
            'user_id': user.id,
            'email': user.email,
            'exp': timezone.now() + timezone.timedelta(minutes=10),
            'iat': timezone.now()
        }
    elif forgot_password:
        refresh_token_payload = {
            'user_id': user.id,
            'exp': timezone.now() + timezone.timedelta(minutes=10),
            'iat': timezone.now()
        }
    else:
        refresh_token_payload = {
            'user_id': user.id,
            'exp': timezone.now() + timezone.timedelta(days=14),
            'iat': timezone.now()
        }
    refresh_token = jwt.encode(
        refresh_token_payload, settings.SECRET_KEY, algorithm='HS256')

    return refresh_token


def generate_security_code():
    digits = [i for i in range(0, 10)]

    random_str = ""

    for i in range(6):
        index = math.floor(random.random() * 10)
        random_str += str(digits[index])

    return random_str


def email_2fa(user):
    data = {
        'subject': 'Security Code',
        'body': '''Hello {},
    Here\'s your security code: {}
    '''.format(user.name, user.security_code),
        'to_address': [user.email],
    }
    send_mail(
        data['subject'],
        data['body'],
        settings.OSCAR_FROM_EMAIL,
        data['to_address']
    )


def send_email_verification_link(user, request):
    token = generate_refresh_token(user, True, False)
    domain = get_current_site(request).domain
    relative_link = reverse('verify email')
    absolute_url = 'http://' + domain + relative_link + '?token=' + str(token)
    data = {
        'subject': 'Confirm your email address',
        'body': '''Hello {},
    please visit the following link to confirm your email address: {}
    '''.format(user.name, absolute_url),
        'to_address': [user.email],
    }
    send_mail(
        data['subject'],
        data['body'],
        settings.OSCAR_FROM_EMAIL,
        data['to_address']
    )


def send_forgot_password_email(user, request):
    token = generate_refresh_token(user, False, True)
    domain = get_current_site(request).domain
    domain = str(domain).replace(domain.rpartition(':')[-1], "8000")
    relative_link = reverse('forgot password page')
    absolute_url = 'http://' + domain + relative_link + '?token=' + str(token)
    data = {
        'subject': 'Reset PayAt password',
        'body': '''Hello {},
        please visit the following link to reset your password: {}
        '''.format(user.name, absolute_url),
        'to_address': [user.email],
    }
    send_mail(
        data['subject'],
        data['body'],
        settings.OSCAR_FROM_EMAIL,
        data['to_address']
    )


def delete_file(file):
    try:
        os.remove(file.path)
    except:
        pass
