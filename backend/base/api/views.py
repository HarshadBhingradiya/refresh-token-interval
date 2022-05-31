from rest_framework import permissions
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

import json
from django.shortcuts import render
from .serializers import RegisterSerializer, ChangePasswordSerializer
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from base.models import User
from rest_framework import generics
from rest_framework.views import APIView
from django.contrib.auth import logout
from django.http import JsonResponse
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_205_RESET_CONTENT, HTTP_401_UNAUTHORIZED
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from django.contrib.auth import authenticate

from django.contrib.auth.forms import PasswordResetForm
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import send_mail, BadHeaderError
from django.conf import settings


from .serializers import NoteSerializer
from base.models import Note


class Login(APIView):
    def post(self, request):
        # try:
            # body_unicode = request.body.decode('utf-8')
            body_data = request.data
            user_exist = User.objects.filter(username=body_data["username"]).exists()
            if user_exist:
                user_object = User.objects.get(username=body_data["username"])
                user = authenticate(username=user_object.username, password=body_data["password"])
                if user is not None:
                    token = RefreshToken.for_user(user_object)
                    refresh_token = str(token)
                    access_token = str(token.access_token)

                    login_response = {
                        "user_id":str(user_object.id),
                        "username": user_object.username,
                        "email": user_object.email,
                        "country": user_object.country,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                    }
                    status = True
                    data = login_response
                    status_code = HTTP_200_OK
                    message = 'User Login Successfully.'

                else:
                    data = {}
                    status = False
                    status_code = HTTP_401_UNAUTHORIZED
                    message = 'Email or Password Is Required.'
            else:
                data = {}
                status = False
                status_code = HTTP_400_BAD_REQUEST
                message = 'Email or Password Is Required.'

            return JsonResponse({'status': status, 'data': data, 'message': message, 'status_code': status_code}, status=status_code)
    
class RegisterView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


class ChangePasswordView(generics.UpdateAPIView):

    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=HTTP_400_BAD_REQUEST)

class PasswordReset(APIView):
	def post(self, request):
		associated_users = User.objects.filter(email=request.POST.get("email"))
		if associated_users.exists():
			for user in associated_users:
				subject = "Password Reset Requested"
				email_template_name = "main/password_reset_email.txt"
				c = {
				"email":user.email,
				'domain':'127.0.0.1:8000',
				'site_name': 'Website',
				"uid": urlsafe_base64_encode(force_bytes(user.pk)),
				"user": user,
				'token': default_token_generator.make_token(user),
				'protocol': 'http',
				}
				email = render_to_string(email_template_name, c)

				try:
					send_mail(subject, email, settings.EMAIL_HOST_USER , [user.email], fail_silently=False)
				except BadHeaderError:
					return JsonResponse({'status': False, 'data': {}, 'message': 'Invalid header found.', 'status_code': HTTP_400_BAD_REQUEST, 'errors': {}}, safe=False, status=HTTP_400_BAD_REQUEST)
			return JsonResponse({'status': True, 'data': {}, 'message': 'check your mail box.', 'status_code': HTTP_200_OK, 'errors': {}}, safe=False, status=HTTP_200_OK)	
		else:
			return JsonResponse({'status': False, 'data': {}, 'message': 'email not exisit in database.', 'status_code': HTTP_400_BAD_REQUEST, 'errors': {}}, safe=False, status=HTTP_400_BAD_REQUEST)



@api_view(['GET'])
def getRoutes(request):
    routes = [
        '/api/token',
        '/api/token/refresh',
    ]

    return Response(routes)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getNotes(request):
    user = request.user
    notes = user.note_set.all()
    serializer = NoteSerializer(notes, many=True)
    return Response(serializer.data)
