from django.contrib.auth.forms import UserCreationForm, UserChangeForm

from .models import CustomUser as User


class CustomUserCreationForm(UserCreationForm):

    class Meta:
        model = User
        fields = ['name', 'surname', 'email', 'number']


class CustomUserChangeForm(UserChangeForm):

    class Meta:
        model = User
        fields = ['name', 'surname', 'email', 'number']
