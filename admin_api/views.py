from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination

from authentication.models import SellerApplication, SellerStore
from authentication.serializers import SellerApplicationSerializer



class GetSellerApplications(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        applications = SellerApplication.objects.all().order_by('-created')

        paginator = PageNumberPagination()
        paginator.page_size = 10

        paginated_products = paginator.paginate_queryset(applications, request=request)

        serializer = SellerApplicationSerializer(paginated_products, many=True)

        return paginator.get_paginated_response(serializer.data)



class ApproveRejectSellerApplication(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        seller_application_id = request.data.get('application_id')

        application = SellerApplication.objects.get(id=int(seller_application_id))

        seller_store = SellerStore.objects.get(id = application.seller_store.id)

        application.is_approved = True
        seller_store.is_approved = True

        application.save()
        seller_store.save()

        return Response("Seller Application Approved Successfully",status=status.HTTP_200_OK)
    
    def delete(self, request):

        seller_application_id = request.data.get('application_id')
        rejection_reason = request.data.get('reason_to_reject')

        application = SellerApplication.objects.get(id=int(seller_application_id))

        seller_store = SellerStore.objects.get(id = application.seller_store.id)

        application.is_rejected = True
        application.rejection_reason = rejection_reason
        seller_store.is_rejected = True
        seller_store.reason_to_reject = rejection_reason

        application.save()
        seller_store.save()

        return Response("Seller Application Rejected",status=status.HTTP_200_OK)
    