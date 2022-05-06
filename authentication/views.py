from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User
from .serializers import LoginSerializer, UserSerializer, RegistrationSerializer, ActivitySerializer



# TODO: SMS code check on registration here or/and serializer


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


# TODO: SMS check here or in serializer

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


class UsersViewSet(ListAPIView):
    """
    API endpoint that allows users to be viewed or edited.
    """
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserSerializer


class ActivityViewSet(ListAPIView):

    permission_classes = [IsAuthenticated]
    serializer_class = ActivitySerializer
    queryset = User.objects.filter(last_login__isnull=False)

    # def get(self, request, *args, **kwargs):
    #     key = self.request.data['username']
    #     key = self.request.user.username
    #     data = cache.get(key)
    #     if data is not None:
    #         return Response(data, status=status.HTTP_200_OK)
    #     else:
    #         return Response('User has no recent activity records or cache expired',
    #                         status=status.HTTP_200_OK)
