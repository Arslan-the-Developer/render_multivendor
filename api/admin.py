from django.contrib import admin

from .models import Product, ProductReview, ReviewImage, UserCart, CartItem, UserOrder, UserOrderItem, SellerOrder, SellerOrderItem, Wishlist, SellerRevenueMonth, UserDeliveryAddress, ProductVariant, ProductImage, ProductVariantCategory

# Register your models here.

admin.site.register(Product)
admin.site.register(ProductImage)
admin.site.register(ProductVariantCategory)
admin.site.register(ProductVariant)
admin.site.register(ProductReview)
admin.site.register(ReviewImage)
admin.site.register(UserCart)
admin.site.register(CartItem)
admin.site.register(UserOrder)
admin.site.register(UserOrderItem)
admin.site.register(SellerOrder)
admin.site.register(SellerOrderItem)
admin.site.register(Wishlist)
admin.site.register(SellerRevenueMonth)
admin.site.register(UserDeliveryAddress)