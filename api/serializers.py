from rest_framework import serializers

from .models import Product, ProductImage, ProductReview, ReviewImage, UserCart, CartItem, UserOrder, UserOrderItem, Wishlist, SellerRevenueMonth, UserDeliveryAddress, SellerOrder, SellerOrderItem, ProductVariant
from authentication.models import SellerStore, User

from django.db.models import Avg





class UserSerializer(serializers.ModelSerializer):

    class Meta:

        model = User
        fields = ['username','user_profile_image','email']



class UserDeliveryAddressSerializer(serializers.ModelSerializer):

    user = UserSerializer()

    class Meta:

        model = UserDeliveryAddress
        fields = ['id','user','address','is_default']



class SellerStoreSerializer(serializers.ModelSerializer):

    class Meta:

        model = SellerStore
        fields = ["id","store_name","store_image","store_category",'store_contact_number','store_country', 'store_address']



class ProductImageSerializer(serializers.ModelSerializer):

    class Meta:

        model = ProductImage
        fields = ['image']  # Avoid nesting product inside image serializer unless required


class ProductVariantSerializer(serializers.ModelSerializer):

    class Meta:

        model = ProductVariant
        fields = ['variant_name','variant_image']



class ProductSerializer(serializers.ModelSerializer):
    
    # Nest the images in the product serializer

    product_store = SellerStoreSerializer()
    product_images = ProductImageSerializer(many=True, read_only=True)
    average_rating = serializers.SerializerMethodField()
    is_product_in_cart = serializers.SerializerMethodField()
    is_product_in_wishlist = serializers.SerializerMethodField()
    product_variants = ProductVariantSerializer(many=True, read_only=True)

    class Meta:
        
        model = Product
        fields = ['id','product_store', 'product_name', 'product_price', 'product_quantity', 'product_sub_category' ,'product_description', 'product_keywords' ,'product_images','average_rating','is_product_in_cart','is_product_in_wishlist','sold_count','product_variants']

    def get_average_rating(self, obj):

        average_rating_dict = obj.product_reviews.aggregate(Avg('review_rating'))
        
        average_rating = average_rating_dict['review_rating__avg']

        if average_rating is None:

            return 0

        return average_rating if average_rating > 0 else "Not Rated Yet"
    

    def get_is_product_in_cart(self, obj):

        user = self.context.get('authenticated_user')
        # Ensure request and user are available
        if user is not None:

            try:

                user_cart, created = UserCart.objects.get_or_create(user=user)

                return CartItem.objects.filter(cart=user_cart, product=obj).exists()
            
            except UserCart.DoesNotExist:

                return "failed to retrieve user's cart"
        # Return False for unauthenticated users

        return "unauthenticated"
    
    
    def get_is_product_in_wishlist(self, obj):

        user = self.context.get('authenticated_user')
        # Ensure request and user are available
        if user is not None:

            try:

                user_wishlist, created = Wishlist.objects.get_or_create(user=user)

                return Wishlist.objects.filter(user=user, products=obj).exists()
            
            except UserCart.DoesNotExist:

                return "failed to retrieve user's wishlist"
        # Return False for unauthenticated users

        return "unauthenticated"




class ReviewImageSerializer(serializers.ModelSerializer):

    class Meta:

        model = ReviewImage
        fields = ['image']



class ReviewSerializer(serializers.ModelSerializer):

    user = UserSerializer()
    review_images = ReviewImageSerializer(many=True, read_only=True)

    class Meta:

        model = ProductReview
        fields = ['user','review_text','review_rating','created','review_images']



class CartItemSerializer(serializers.ModelSerializer):

    product = ProductSerializer()

    class Meta:

        model = CartItem

        fields = ['product','quantity']




class UserOrderItemSerializer(serializers.ModelSerializer):

    product = ProductSerializer()

    class Meta:

        model = UserOrderItem

        fields = ['product','product_quantity']




class UserOrderSerializer(serializers.ModelSerializer):

    user = UserSerializer()
    order_items = UserOrderItemSerializer(many=True)

    class Meta:

        model = UserOrder
        fields = ['id','user','created_at','order_total','is_delivered', 'is_paid', 'order_items']




class WishlistSerializer(serializers.ModelSerializer):
    
    user = UserSerializer()
    products = ProductSerializer(many=True)

    class Meta:

        model = Wishlist
        fields = ['user','products']




class RevenueMonthSerializer(serializers.ModelSerializer):
    
    seller_store = SellerStoreSerializer()

    class Meta:

        model = SellerRevenueMonth
        fields = ['seller_store','month_name','month_year','revenue_amount']




class SellerOrderItemSerializer(serializers.ModelSerializer):

    product = ProductSerializer()

    class Meta:

        model = SellerOrderItem
        fields = ['product','product_quantity']



class SellerOrderSerializer(serializers.ModelSerializer):

    seller_order_items = SellerOrderItemSerializer(many=True)
    order = UserOrderSerializer()

    class Meta:

        model = SellerOrder
        fields = ['id','created_at','order_amount','seller_order_items','order']