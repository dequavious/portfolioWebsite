from django.contrib.auth.hashers import make_password
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField


class MyAccountManager(BaseUserManager):
    def create_user(self, email, name, surname, number, password):
        if not email:
            raise ValueError("must have email")
        if not name:
            raise ValueError("must have name")
        if not surname:
            raise ValueError("must have surname")
        if not number:
            raise ValueError("must have number")

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            surname=surname,
            number=number,
            password=make_password(password),
        )

        user.save(using=self.db)

        return user

    def create_superuser(self, email, name, surname, number, password):
        return self.create_user(email, name, surname, number, password)


class CustomUser(AbstractBaseUser):
    email = models.EmailField(verbose_name="email", max_length=60, unique=True)
    token_last_expired = models.DateTimeField(default=timezone.now)
    security_code = models.fields.CharField(default=None, max_length=6, null=True, blank=True)
    authenticated = models.BooleanField(default=False)
    name = models.CharField(max_length=30, unique=True)
    surname = models.CharField(max_length=30)
    picture = models.ImageField(default=None, upload_to='images', max_length=256, null=True, blank=True)
    bio = models.CharField(default=None, max_length=1000, null=True, blank=True)
    number = PhoneNumberField(unique=True)
    dob = models.DateField(default='1998-10-20')
    is_active = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'surname', 'number']

    objects = MyAccountManager()


class Address(models.Model):
    street = models.CharField(max_length=60)
    suburb = models.CharField(max_length=60)
    city = models.CharField(max_length=60)
    postal_code = models.CharField(max_length=60)
    province = models.CharField(max_length=60)
    country = models.CharField(max_length=60)


class Language(models.Model):
    language = models.CharField(unique=True, max_length=30)
    confidence = models.CharField(max_length=256)
    avatar = models.ImageField(default=None, upload_to='images', max_length=256, null=True, blank=True)


class Framework(models.Model):
    framework = models.CharField(unique=True, max_length=30)
    confidence = models.CharField(max_length=256)
    avatar = models.ImageField(default=None, upload_to='images', max_length=256, null=True, blank=True)


class DBMS(models.Model):
    dbms = models.CharField(unique=True, max_length=30)
    confidence = models.CharField(max_length=256)
    avatar = models.ImageField(default=None, upload_to='images', max_length=256, null=True, blank=True)


class Hobby(models.Model):
    hobby = models.CharField(unique=True, max_length=30)
    avatar = models.ImageField(default=None, upload_to='images', max_length=256, null=True, blank=True)

    def __str__(self):
        return self.hobby


class Skill(models.Model):
    skill = models.CharField(unique=True, max_length=256)

    def __str__(self):
        return self.skill


class Document(models.Model):
    file = models.FileField(upload_to='documents')
    type = models.CharField(max_length=30)

    def __str__(self):
        return self.file


class Work(models.Model):
    description = models.CharField(unique=True, max_length=60)
    company = models.CharField(max_length=60)

    def __str__(self):
        return self.description


class Project(models.Model):
    description = models.CharField(unique=True, max_length=256)
    git = models.CharField(unique=True, max_length=256)
    link = models.CharField(unique=True, max_length=256)

    def __str__(self):
        return self.description


class Education(models.Model):
    degree = models.CharField(max_length=60)
    year = models.PositiveBigIntegerField()
    grade = models.CharField(default=None, max_length=256, null=True, blank=True)
    institution = models.CharField(max_length=60)

    def __str__(self):
        return self
