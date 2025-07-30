from django.urls import path
from . import views

urlpatterns = [

    path('get_user_details', views.GetUserDetails.as_view()),
    
    path('get_user_delivery_addresses', views.GetUserDeliveryAddresses.as_view()),
    
    path('create_user_delivery_address', views.CreateUserDeliveryAddress.as_view()),

    path('delete_user_delivery_address', views.DeleteUserAddress.as_view()),
    
    path('get_seller_details', views.GetSellerDetails.as_view()),

    path('get_product_subcategories', views.GetSubCategoriesFromParent.as_view()),
    
    path('create_product', views.CreateProduct.as_view()),

    path('create_test_product', views.TestCreateProduct.as_view()),

    path('get_all_products/', views.GetAllProducts.as_view()),
    
    path('get_category_products/<str:product_category>', views.GetCategoryProducts.as_view()),

    path('get_product_details', views.GetProductDetails.as_view()),
    
    path('modify_product/<str:id>', views.ModifyProduct.as_view()),
    
    path('user_search_products/<str:search_word>', views.ProductsSearchView.as_view()),

    path('get_store_products', views.GetStoreProducts.as_view()),

    path('validate_payment_page',views.ValidatePaymentPage.as_view()),

    path('get_client_secret',views.GetClientSecret.as_view()),

    path('create_product_review', views.AddProductReview.as_view()),
    
    path('get_product_reviews', views.GetProductReviews.as_view()),
    
    path('add_modify_cart_product', views.AddModifyCartProduct.as_view()),
    
    path('create_user_cart_order', views.CreateUserCartOrder.as_view()),
    
    path('create_user_product_order', views.CreateUserProductOrder.as_view()),
    
    path('mark_order_as_paid', views.MarkOrderAsPaid.as_view()),

    path('get_user_order_details', views.GetUserOrderDetails.as_view()),
    
    path('get_user_orders', views.GetUserAllOrders.as_view()),
    
    path('get_user_wishlist', views.GetUserWishlist.as_view()),
    
    path('add_remove_wishlist_product', views.AddRemoveWishlistProduct.as_view()),
    
    path('get_user_cart_products', views.GetUserCartProducts.as_view()),
    
    path('clear_user_cart', views.ClearUserCart.as_view()),
    
    path('get_seller_revenue_months', views.GetSellerAllRevenueMonths.as_view()),

    path('get_seller_orders', views.GetSellerAllOrders.as_view()),
    
    path('get_seller_dashboard_details', views.GetSellerDashboardDetails.as_view()),

]