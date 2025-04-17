from django.urls import path
from . import views


urlpatterns = [

    path('get_all_seller_applications', views.GetSellerApplications.as_view()),
    
    path('approve_reject_seller_application', views.ApproveRejectSellerApplication.as_view()),

]