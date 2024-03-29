from rest_framework.authentication import authenticate
from rest_framework import serializers
from .models import User


class RegistrationSerializer(serializers.ModelSerializer):
    """
    Creates a new user, returns JWT
    """

    password = serializers.CharField(
        max_length=32,
        min_length=8,
        write_only=True,
    )

    # `token` read-only handles
    token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ('email', 'username', 'password', 'token',)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    """
    Authenticates an existing user.
    Email and password are required.
    Returns a JSON web token.
    """
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(max_length=128, write_only=True)

    # Ignore these fields if they are included in the request.
    username = serializers.CharField(max_length=32, read_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, data):
        """
        Validates user data.
        """
        email = data.get('email', None)
        password = data.get('password', None)

        if email is None:
            raise serializers.ValidationError(
                'An email address is required to log in.'
            )

        if password is None:
            raise serializers.ValidationError(
                'A password is required to log in.'
            )

        try:
            # declare email as username for get_by_natural_key method
            user = authenticate(username=email, password=password)
            if user:
                try:
                    if user is None:
                        raise serializers.ValidationError(
                            'A user with this email and password was not found.')

                    if not user.is_active:
                        raise serializers.ValidationError(
                            'This user has been deactivated')

                finally:
                    return {
                        'username': user.username,
                        'email': user.email,
                        # 'is_staff': user.is_staff,
                        # 'is_active': user.is_active,
                        # 'last_login': user.last_login,
                        # 'pk': user.pk,
                        # 'is_superuser': user.is_superuser,
                        'token': user.token,
                    }
        except KeyError as e:
            raise serializers.ValidationError('Please provide a email and a password')
        except User.DoesNotExist:
            raise serializers.ValidationError('User does not exist')


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('email', 'username', 'is_superuser', 'is_active', 'last_login')
