from rest_framework import status
from django.core.cache import cache
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User
from .serializers import LoginSerializer, UserSerializer, RegistrationSerializer


class RegistrationAPIView(APIView):
    """
    Registers a new user.
    """
    permission_classes = [AllowAny]
    serializer_class = RegistrationSerializer

    def post(self, request):
        """
        Creates a new User object.
        Username, email, and password are required.
        Returns a JSON web token.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {
                'token': serializer.data.get('token', None),
            },
            status=status.HTTP_201_CREATED,
        )


class LoginAPIView(APIView):
    """
    Logs in an existing user.
    """
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        """
        Email and password are required.
        Returns a JSON web token.
        """
        serializer = self.serializer_class(data=request.data)
        # on ValidationError include meaningful response
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UsersViewSet(ListCreateAPIView):
    """
    API endpoint that allows users to be viewed or edited.
    """
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserSerializer


class ActivityViewSet(ListCreateAPIView):
    """
    API endpoint that accepts username in parameters
    Shows last activity of a user with given username.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        key = self.request.data['username']
        data = cache.get(key)
        if data is not None:
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response('User has no recent activity records or cache expired',
                            status=status.HTTP_200_OK)
