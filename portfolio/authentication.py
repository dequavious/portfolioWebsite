import jwt

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from django.conf import settings
from django.middleware.csrf import CsrfViewMiddleware

from .models import CustomUser as User


class CSRFCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        return reason


class JWTAuthentication(TokenAuthentication):
    def authenticate(self, request):

        authorization_header = request.headers.get('Authorization')

        if not authorization_header:
            return None
        try:
            token = authorization_header.split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('token expired')
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed('invalid token')
        except IndexError:
            raise exceptions.AuthenticationFailed('Token prefix missing')

        user = User.objects.filter(id=payload['user_id']).first()
        if user is None:
            raise exceptions.AuthenticationFailed('User not found')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('user is inactive')

        iat = int(payload['iat'])
        token_last_expired = int(user.token_last_expired.timestamp())
        if iat < token_last_expired:
            msg = 'token expired'
            raise exceptions.AuthenticationFailed(msg)

        self.enforce_csrf(request)
        return user, None

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation
        """
        check = CSRFCheck()
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)
