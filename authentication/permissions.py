from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken

from authentication.models import User


class CookieJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Retrieve token from cookies
        access_token = request.COOKIES.get('access')

        if not access_token:
            return None  # No token, proceed to next authentication class
        
        try:
            # Validate the token
            validated_token = AccessToken(access_token)

            user = User.objects.get(id=validated_token['user_id'])

        except Exception as e:
            
            raise AuthenticationFailed(f'Invalid token or expired token {e}')

        # Return the user and token
        return (user, validated_token)  # Adjust user fetching logic as needed


class IsSeller(permissions.BasePermission):

    def has_permission(self, request, view):

        if not request.user.is_seller:

            raise PermissionDenied(detail="Only Sellers Can Access This Resource")
        
        return True
    

class IsApprovedSeller(permissions.BasePermission):

    def has_object_permission(self, request, view):
        
        seller_store = request.user.seller_profile

        if not seller_store.is_approved:

            raise PermissionDenied(detail="Your Seller Account Isn't Approved Yet")
        
        return True