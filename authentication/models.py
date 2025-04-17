from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.utils import timezone
from django.db.models import signals
from django.dispatch import receiver
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password

import uuid


class MyUserManager(BaseUserManager):
    def create_user(self, email : str, username : str, password=None):

        """
        Creates and saves a User with the given email, username and password.
        """

        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None):

        """
        Creates and saves a superuser with the given email, username and password.
        """

        user = self.create_user(
            email,
            password=password,
            username=username,
        )

        user.is_admin = True
        user.is_staff_member = True
        user.is_active = True
        user.save(using=self._db)
        return user



class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name="email address",
        max_length=255,
        unique=True,
    )
    
    username = models.CharField(max_length=100)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_staff_member = models.BooleanField(default=False)
    user_profile_image = models.ImageField(upload_to="User Profiles", null=True, blank=True, default=None)
    verification_token = models.CharField(blank=True,null=True,unique=True,max_length=60)
    verification_token_expiry = models.DateTimeField(blank=True,null=True)
    otp = models.CharField(blank=True,null=True,unique=True,max_length=4)
    otp_expiry = models.DateTimeField(blank=True,null=True)
    is_seller = models.BooleanField(default=False)
    is_two_factor_authentication_enabled = models.BooleanField(default=False)
    two_factor_pin = models.CharField(max_length=255, blank=True, null=True)


    objects = MyUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    
    def set_two_factor_pin(self, raw_pin):

        """
        Sets The Hashed Two Factor Authentication PIN
        """

        self.two_factor_pin = make_password(raw_pin)

    
    def verify_two_factor_pin(self, raw_pin):

        """
        Verify The Hashed Two Factor PIN. Inputs A Raw PIN To Match
        """

        return check_password(raw_pin, self.two_factor_pin)


    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin or self.is_staff_member
    


class SellerStore(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="seller_profile")

    store_name = models.CharField(max_length=255,null=True,blank=True)

    store_image = models.ImageField(upload_to="store_images",null=True,blank=True)

    CATEGORY_CHOICES = [
        ('electronics', 'Electronics'),('fashion', 'Fashion & Clothing'),('beauty', 'Beauty & Personal Care'),('home', 'Home & Kitchen'),('sports   ', 'Sports & Outdoors'),('books', 'Books & Stationery'),('health', 'Health & Wellness'),('toys', 'Toys & Games'),('automotive', 'Automotive'),('jewelry', 'Jewelry & Accessories'),('grocery', 'Grocery & Food'),('baby', 'Baby Products'),('furniture', 'Furniture & Decor'),('pet', 'Pet Supplies'),('office', 'Office Supplies'),
        ]

    store_category = models.CharField(max_length=50, choices=CATEGORY_CHOICES,null=True,blank=True)

    store_contact_number = models.CharField(max_length=10,null=True,blank=True,unique=True)

    store_address = models.TextField(null=True,blank=True)

    store_country = models.CharField(max_length=50,null=True,blank=True)

    is_approved = models.BooleanField(default=False)

    is_rejected = models.BooleanField(default=False)

    reason_to_reject = models.CharField(default="", max_length=256)

    
    def __str__(self) -> str:

        return f"{str(self.user.username)}'s Store"




class SellerIDInformation(models.Model):

    store = models.OneToOneField(SellerStore, on_delete=models.CASCADE, related_name="store_id_info")

    store_id_card_number = models.CharField(max_length=30)

    id_card_name = models.CharField(max_length=50)

    def __str__(self) -> str:
        return f"{self.store.store_name}'s ID Info"




class SellerIDCardImage(models.Model):

    store_id_info = models.ForeignKey(SellerIDInformation, on_delete=models.CASCADE, related_name='seller_id_images')

    image = models.ImageField(upload_to="seller_id_images", validators=[FileExtensionValidator(allowed_extensions=['png','jpg'])])

    def clean(self):
        if self.parent.childmodel_set.count() > 2:
            raise ValidationError(f"Maximum Limit of {self.store_id_info.store.store_name}'s ID Images Reached")
        super().clean()

    def __str__(self) -> str:
        return f"{self.store_id_info.store.store_name}'s ID Image"




class SellerApplication(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)

    seller_store = models.OneToOneField(SellerStore, on_delete=models.CASCADE)

    seller_id_info = models.OneToOneField(SellerIDInformation, on_delete=models.CASCADE)

    is_approved = models.BooleanField(default=False)
    
    is_rejected = models.BooleanField(default=False)

    rejection_reason = models.CharField(default="", max_length=256)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        
        return f"{self.user.username}'s Application For {self.seller_store.store_name} (Store)"




class LoginAttempt(models.Model):
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    success = models.BooleanField(default=False)




class OTPVerifyAttempt(models.Model):
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    success = models.BooleanField(default=False)



class TwoStepVerificationAttempt(models.Model):
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    success = models.BooleanField(default=False)




class CardDetails(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="card_details")
    card_holder_name = models.CharField(max_length=100)
    card_number = models.CharField(max_length=16)  # Mask or encrypt this in a real scenario
    expiry_date = models.DateField()
    card_type = models.CharField(max_length=20, choices=[('credit', 'Credit Card'), ('debit', 'Debit Card')])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s {self.card_type} Card"
    



class PaymentMethod(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="payment_methods")
    card_details = models.OneToOneField(CardDetails, on_delete=models.CASCADE, null=True, blank=True)
    is_default = models.BooleanField(default=False)  # Optional: mark as default payment method
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Payment Method"