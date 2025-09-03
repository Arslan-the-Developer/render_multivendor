from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from authentication.models import User, SellerStore, SellerApplication, SellerIDInformation, SellerIDCardImage
from api.views import compress_image

from api.serializers import UserSerializer, SellerStoreSerializer

import requests
from PIL import Image
from django.conf import settings

from api.views import check_image_exploitation, compress_image



class UserRegistrationSerializer(serializers.ModelSerializer):

    password2 = serializers.CharField(write_only=True)  # Explicitly define password2

    class Meta:

        model = User

        fields = ['username','email','password','password2']


    def validate(self, attrs):

        # FOR THE VALIDATION OF EMAIL PROVIDERS | UNCOMMENT THIS WHEN NEEDED

        # valid_mails_list = ["gmail.com","outlook.com","aol.com","protonmail.com","zoho.com","gmx.com","icloud.com","yahoo.com","mail2world.com","tutanota.com","juno.com"]

        # if attrs['email'] not in valid_mails_list:

        #     raise ValidationError(detail="Disposable Emails Are Not Allowed")
        
        if len(attrs['password']) < 8:

            raise ValidationError(detail="Password Must Have 8 Characters")
        
        if attrs['password'] != attrs['password2']:

            raise ValidationError(detail="Passwords Must Match")
        
        return attrs
    
    def create(self, validated_data):
        
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email']
        )

        user.set_password(validated_data['password'])

        user.save()
        
        return user




class SellerRegistrationSerializer(serializers.Serializer):

    store_contact_number = serializers.CharField()

    def validate(self, attrs):
        
        store_contact_number = attrs.get('store_contact_number')
        
        if store_contact_number is None or len(store_contact_number) < 10 or not (str(store_contact_number).isnumeric()):
        
            raise ValidationError(detail="Please enter a correct phone number")
        
        elif store_contact_number[0] != "3":
        
            raise ValidationError(detail="Phone Number Should Start with ' 3 '")
        
        elif SellerStore.objects.filter(store_contact_number=store_contact_number).exists():

            raise ValidationError(detail="Seller with This Phone Already Exists")

        return attrs
    
    
    def create(self, validated_data):

        # Functions Imported Here To Avoid Circular Dependency or Partial Initialization

        from .views import assign_otp, assign_verification_token
        
        user = self.context['request'].user

        assign_verification_token(user=user)
        assign_otp(user=user)

        new_seller_store = SellerStore.objects.create(user=user,store_contact_number=validated_data['store_contact_number'])
        

        # Here Must Add The SMS Functionality

        message = {
            "secret": settings.SMS_CHEF_API_SECRET,
            "mode": "devices",
            "device": "c73edcf13f788560",
            "sim": 2,
            "priority": 1,
            "phone": f"+92{validated_data['store_contact_number']}",
            "message": f"Howdy {user.username}! Here's Your Seller Account OTP : {user.otp}"
        }

        r = requests.post(url = "https://www.cloud.smschef.com/api/send/sms", params = message)

        # do something with response object
        sms_send_result = r.json()

        return (new_seller_store,user.verification_token,sms_send_result)




class SellerUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        
        model = SellerStore
        fields = ['store_name', 'store_category', 'store_image', 'store_address', 'store_country']

    def validate(self, attrs):
        
        store_name = attrs.get('store_name', None)
        store_category = attrs.get('store_category', None)
        store_image = attrs.get('store_image', None)
        store_address = attrs.get('store_address', None)
        store_country = attrs.get('store_country', None)

        if not store_name:
            raise ValidationError({"store_name": "Enter a valid store name."})

        if not store_category:
            raise ValidationError({"store_category": "Enter a valid store category."})

        if not store_image:
            raise ValidationError({"store_image": "Store image is required."})
        
        if not store_address:
            raise ValidationError({"store_address": "Store Address is required."})
        
        if not store_country:
            raise ValidationError({"store_country": "Store Country is required."})

        return attrs
        

    def update(self, instance, validated_data):
        
        instance.store_name = validated_data['store_name']
        instance.store_category = validated_data['store_category']
        incoming_image = validated_data['store_image']
        instance.store_address = validated_data['store_address']
        instance.store_country = validated_data['store_country']

        try:
            # Verify that the incoming file is an actual image
            image = Image.open(incoming_image)
            image.verify()

            # Compress the image first, as the API expects a compressed image
            compressed_image = compress_image(image=incoming_image)

            # Check for explicit content on the compressed image
            exploitation_result = check_image_exploitation(image=compressed_image)

            if not exploitation_result[0]:
                raise ValidationError(f"{exploitation_result[1]}")

            # Assign the compressed image to the instance after validation
            instance.store_image = compressed_image

        except (IOError, SyntaxError) as e:

            raise ValidationError("File Isn't an Actual Image")

        
        instance.store_image = compress_image(image=incoming_image)

        instance.save()

        return instance
        


class IDImageSerializer(serializers.ModelSerializer):

    class Meta:

        model = SellerIDCardImage
        fields = ['image']


class SellerIDInfoSerializer(serializers.ModelSerializer):

    seller_id_images = IDImageSerializer(many=True, read_only=True)

    class Meta:

        model = SellerIDInformation

        fields = ['store_id_card_number','id_card_name','seller_id_images']



class SellerApplicationSerializer(serializers.ModelSerializer):

    user = UserSerializer()
    seller_store = SellerStoreSerializer()
    seller_id_info = SellerIDInfoSerializer()

    class Meta:

        model = SellerApplication
        fields = ['id','user','seller_store', 'seller_id_info', 'is_rejected', 'is_approved', 'created']