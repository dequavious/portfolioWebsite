# Generated by Django 3.2.9 on 2022-01-02 23:51

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=60, unique=True, verbose_name='email')),
                ('token_last_expired', models.DateTimeField(default=django.utils.timezone.now)),
                ('security_code', models.CharField(blank=True, default=None, max_length=6, null=True)),
                ('authenticated', models.BooleanField(default=False)),
                ('name', models.CharField(max_length=30, unique=True)),
                ('surname', models.CharField(max_length=30)),
                ('picture', models.ImageField(blank=True, default=None, max_length=256, null=True, upload_to='images')),
                ('bio', models.CharField(blank=True, default=None, max_length=1000, null=True)),
                ('number', phonenumber_field.modelfields.PhoneNumberField(max_length=128, region=None, unique=True)),
                ('dob', models.DateField(default='1998-10-20')),
                ('is_active', models.BooleanField(default=False)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Address',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('street', models.CharField(max_length=60)),
                ('suburb', models.CharField(max_length=60)),
                ('city', models.CharField(max_length=60)),
                ('postal_code', models.CharField(max_length=60)),
                ('province', models.CharField(max_length=60)),
                ('country', models.CharField(max_length=60)),
            ],
        ),
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='documents')),
                ('type', models.CharField(max_length=30)),
            ],
        ),
        migrations.CreateModel(
            name='Education',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('degree', models.CharField(max_length=60)),
                ('year', models.PositiveBigIntegerField()),
                ('grade', models.CharField(blank=True, default=None, max_length=256, null=True)),
                ('institution', models.CharField(max_length=60)),
            ],
        ),
        migrations.CreateModel(
            name='Hobby',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hobby', models.CharField(max_length=30, unique=True)),
                ('avatar', models.ImageField(blank=True, default=None, max_length=256, null=True, upload_to='images')),
            ],
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=60, unique=True)),
                ('description', models.CharField(max_length=1000, unique=True)),
                ('git', models.CharField(blank=True, max_length=256, null=True, unique=True)),
                ('link', models.CharField(blank=True, max_length=256, null=True, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Quote',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quote', models.CharField(max_length=256, unique=True)),
                ('author', models.CharField(max_length=256, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Skill',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('skill', models.CharField(max_length=256, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Technology',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=30, unique=True)),
                ('type', models.CharField(max_length=256)),
                ('confidence', models.CharField(max_length=256)),
                ('avatar', models.ImageField(max_length=256, upload_to='images')),
            ],
        ),
        migrations.CreateModel(
            name='Work',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=60)),
                ('company', models.CharField(max_length=60)),
            ],
        ),
        migrations.CreateModel(
            name='ProjectStack',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='portfolio.project')),
                ('technology', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='portfolio.technology')),
            ],
        ),
    ]
