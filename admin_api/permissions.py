from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import User


class IsManager(permissions.BasePermission):

    def has_permission(self, request, view):

        if not request.user.is_manager:

            raise PermissionDenied(detail="Only Site Managers Can Access This Resource")
        
        return True