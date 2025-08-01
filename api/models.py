from django.db import models
from django.db.models import signals
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator

from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField

from authentication.models import SellerStore, User

import uuid

# Create your models here.


class Product(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    product_store = models.ForeignKey(SellerStore, on_delete=models.CASCADE, related_name="store_products")
    product_name = models.CharField(max_length=255, db_index=True)
    product_description = models.TextField()
    product_keywords = models.TextField(default="")
    product_sub_category = models.CharField(max_length=50, null=True, blank=True)
    sold_count = models.PositiveIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    search_vector = SearchVectorField(null=True, blank=True)
    
    def __str__(self) -> str:
        return f"{self.product_name} | {self.product_store.store_name}"


    class Meta:

        unique_together = ['product_store','product_name']
        indexes = [
            GinIndex(fields=['search_vector'])
        ]
    




class ProductImage(models.Model):

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="product_images")
    image = models.ImageField(upload_to="product_images",validators=[FileExtensionValidator(allowed_extensions=['png','jpg'])])

    def __str__(self) -> str:
        return f"Image for {self.product.product_name} | {str(self.product.product_store.store_name)}"



class ProductVariant(models.Model):

    product = models.ForeignKey(Product,on_delete=models.CASCADE,related_name='product_variants')
    variant_name = models.CharField(max_length=50)
    variant_price = models.PositiveBigIntegerField(default=0)
    variant_quantity = models.PositiveIntegerField(default=1)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['product','variant_name'],
                name = 'unique_variant_per_product'
            )
        ]
    
    def __str__(self) -> str:
        return f"Variant {self.variant_name} | {self.product.product_name}"




class VariantImage(models.Model):

    variant = models.ForeignKey(ProductVariant,on_delete=models.CASCADE,related_name='variant_images')
    variant_image = models.ImageField(upload_to="product_variants", validators=[FileExtensionValidator(allowed_extensions=['png','jpg'])], null=True, blank=True)

    def __str__(self) -> str:
        return f"Variant Image Of {self.variant.variant_name} | {self.variant.product.product_name}"



class ProductReview(models.Model):

    user = models.ForeignKey(User, related_name="user_reviews", on_delete=models.CASCADE)

    product = models.ForeignKey(Product, related_name='product_reviews', on_delete=models.CASCADE)

    review_text = models.TextField()

    review_rating = models.PositiveIntegerField()

    created = models.DateTimeField(auto_now_add=True)

    class Meta:

        unique_together = ['user','product']

    
    def __str__(self) -> str:

        return f"{self.user.username}'s Review for {self.product.product_name} - {self.product.product_store.store_name}"





class UserDeliveryAddress(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_delivery_address")

    address = models.TextField(null=True, blank=True)

    is_default = models.BooleanField(default=False, null=True, blank=True)


    def __str__(self):

        return f"{self.user.username}'s Address {self.id}"




class ReviewImage(models.Model):

    review = models.ForeignKey(ProductReview, on_delete=models.CASCADE, related_name="review_images")

    image = models.ImageField(upload_to="review_images", validators=[FileExtensionValidator(allowed_extensions=['png','jpg'])])

    def __str__(self) -> str:

        return f"Image for {self.review.user.username}'s Review for {self.review.product.product_name} - {self.review.product.product_store.store_name}"
    




class UserCart(models.Model):

    user = models.OneToOneField(User, related_name='user_cart', on_delete=models.CASCADE)

    def __str__(self) -> str:

        return f"{self.user.username}'s Cart"





class CartItem(models.Model):

    cart = models.ForeignKey(UserCart, on_delete=models.CASCADE, related_name='cart_items')

    product = models.ForeignKey(Product, on_delete=models.CASCADE)

    quantity = models.PositiveIntegerField(default=1)

    class Meta:

        unique_together = ['cart','product']

    def __str__(self) -> str:
        return f"{self.cart.user.username}'s Cart Item | '{self.product.product_name}' from {self.product.product_store.store_name}"
    




class UserOrder(models.Model):

    user = models.ForeignKey(User , on_delete=models.CASCADE, related_name='user_orders')

    delivery_address = models.TextField(default="")

    created_at = models.DateTimeField(auto_now_add=True)

    order_total = models.PositiveIntegerField(default=0)

    is_paid = models.BooleanField(default=False)

    is_delivered = models.BooleanField(default=False)

    payment_intent_id = models.CharField(max_length=255, null=True, blank=True)


    def __str__(self) -> str:
        return f"{self.user.username}'s Order {str(self.id)}"
    




class UserOrderItem(models.Model):

    order = models.ForeignKey(UserOrder, on_delete=models.CASCADE, related_name="order_items")

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="product_orders")

    product_quantity = models.PositiveIntegerField()


    def __str__(self) -> str:
        return f"{self.order.user.username}'s Order : {self.order.id} Item | {self.product.product_name} | {self.product.product_store.store_name}"
    




class SellerOrder(models.Model):

    seller = models.ForeignKey(SellerStore, on_delete=models.CASCADE, related_name="seller_orders")

    order = models.ForeignKey(UserOrder, on_delete=models.CASCADE, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    order_amount = models.PositiveIntegerField(default=0)

    def __str__(self) -> str:
        return f"Order For {self.seller.store_name} | {self.id}"





class SellerOrderItem(models.Model):

    seller_order = models.ForeignKey(SellerOrder, on_delete=models.CASCADE, related_name="seller_order_items")

    product = models.ForeignKey(Product, on_delete=models.CASCADE)

    product_quantity = models.PositiveIntegerField()

    def __str__(self) -> str:
        return f"Order For {self.product.product_name} | {self.seller_order.seller.store_name}"





class Wishlist(models.Model):


    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="user_wishlist")

    products = models.ManyToManyField(Product)

    def __str__(self) -> str:
        return f"{self.user.username}'s Wishlist"
    




class SellerRevenueMonth(models.Model):

    seller_store = models.ForeignKey(SellerStore, on_delete=models.CASCADE, related_name='store_revene_months')
    month_name = models.CharField(max_length=30)
    month_year = models.PositiveIntegerField()
    revenue_amount = models.PositiveIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return str(self.seller_store.store_name+" , "+self.month_name+" , "+str(self.month_year))