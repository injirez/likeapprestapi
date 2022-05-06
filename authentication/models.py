import jwt
from datetime import datetime
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.core import validators
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.postgres.fields import ArrayField

from phonenumber_field.modelfields import PhoneNumberField

from .utils.cities import CITY_CHOICES
from .utils.genders import GENDER_CHOICES, SEARCH_CHOICES


class UserManager(BaseUserManager):
    """
    own manager, redeclare user creation method
    """

    def _create_user(self, username, email, password=None, **extra_fields):
        if not username:
            raise ValueError('Username needed!')

        if not email:
            raise ValueError('Email address needed!')

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_user(self, username, email, password=None, **extra_fields):
        """
        created regular user.
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email, password, **extra_fields):
        """
        created admin user.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Admin must have is_staff field set to True.')

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Admin must have is_superuser field set to True.')

        return self._create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Declaring our own class User basing on AbstractBaseUser and
    PermissionsMixin classes
    """


    username = models.CharField(db_index=True, max_length=32, unique=True)

    # TODO: fields for city, phone_number, gender, in_search, pin_code, bool(visible)

    email = models.EmailField(
        validators=[validators.validate_email],
        unique=True,
        blank=True
        )

    is_staff = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)

    is_visible = models.BooleanField(default=True)

    city = models.CharField(max_length=100, choices=CITY_CHOICES, blank=False)

    phone_number = PhoneNumberField(unique=True, blank=False)

    # Gives all choices if nothing was selected (default not working)
    # @property
    # def gender_default(self):
    #     return self._get_choice_default(GENDER_CHOICES)
    #
    # @property
    # def search_default(self):
    #     return self._get_choice_default(SEARCH_CHOICES)
    #
    # gender = ArrayField(models.CharField(
    #                                     max_length=20,
    #                                     choices=GENDER_CHOICES,),
    #                                     # dafault=gender_default,
    #                                     # dafault=['Мужчина', 'Женщина', 'Другой вариант']
    #                                     )
    #
    # in_search = ArrayField(models.CharField(
    #                                         max_length=20,
    #                                         choices=SEARCH_CHOICES),
    #                                         # dafault=search_default,
    #                                         # default=['Мужчин', 'Женщин', 'Другой вариант']
    #                                         )

    # May be more usefull
    gender = models.CharField(max_length=50, blank=True)

    in_search = models.CharField(max_length=50, blank=True)

    pin_code = models.CharField(max_length=4, default='0000', blank=False)

    # Set email field for login
    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ('username',)

    # Set manager for User obj
    objects = UserManager()

    # def __str__(self):
    #     return self.username

    # if token already in request ??
    @property
    def token(self):
        return self._generate_jwt_token()

    # def get_full_name(self):
    #     return self.username
    #
    # def get_short_name(self):
    #     return self.username

    def _generate_jwt_token(self):
        """
        Generate JWT that lasts 30 days
        """
        dt = datetime.now() + timedelta(days=30)

        token = jwt.encode({
            'id': self.pk,
            'exp': dt.utcfromtimestamp(dt.timestamp())
        }, settings.SECRET_KEY, algorithm='HS256')

        return token

    def _get_choice_default(self, choices: list) -> list:
        return list(choice[1] for choice in choices)


