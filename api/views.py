
# REST FRAMEWORK DEPENDENCIES

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
import stripe.error


# PROJECT DEPENDENCIES

from authentication.permissions import IsSeller, IsApprovedSeller
from authentication.models import SellerStore, User
from .models import Product, ProductImage, ProductReview, ReviewImage, UserCart, CartItem, UserOrder, UserOrderItem, SellerOrder, SellerOrderItem, Wishlist, SellerRevenueMonth, UserDeliveryAddress, ProductVariant, VariantImage
from .serializers import ProductSerializer, ReviewSerializer, CartItemSerializer, UserOrderSerializer, WishlistSerializer, RevenueMonthSerializer, UserDeliveryAddressSerializer, SellerOrderSerializer

# DJANGO DEPENDENCIES

from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db import IntegrityError, transaction
from django.core.exceptions import ValidationError
from django.conf import settings
from django.db.models import Q, F, FloatField, ExpressionWrapper, Avg, Value
from django.db.models.functions import Coalesce
from django.contrib.postgres.search import SearchVector, SearchQuery, SearchRank


# CORE PYTHON DEPENDENCIES

from PIL import Image
import re , sys, requests, json
from io import BytesIO
import stripe
import json
from datetime import datetime



stripe.api_key = settings.STRIPE_TEST_KEY


class GetUserDetails(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        user_details = {
                "Username": request.user.username,
                "Email": request.user.email,
                # Check if the user has a profile image, and only access the URL if it exists
                "Profile Image": request.user.user_profile_image.url if request.user.user_profile_image and hasattr(request.user.user_profile_image, 'url') else None
            }

        return Response(user_details, status=status.HTTP_200_OK)



class GetUserDeliveryAddresses(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        delivery_addresses = UserDeliveryAddress.objects.filter(user=request.user)

        if request.user.user_delivery_address.all().count() < 1:

            return Response({"exists" : False}, status=status.HTTP_200_OK)

        serializer = UserDeliveryAddressSerializer(delivery_addresses, many=True)

        return Response({"exists" : True, "addresses" : serializer.data}, status=status.HTTP_200_OK)




class CreateUserDeliveryAddress(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        incoming_address = request.data.get("delivery_address",None)
        incmoing_default_status = request.data.get('is_default',False)

        if incmoing_default_status=='on':

            current_defualt_address = UserDeliveryAddress.objects.get(user=request.user, is_default=True)

            current_defualt_address.is_default = False

            current_defualt_address.save()


        if UserDeliveryAddress.objects.filter(user=request.user).count() == 0:

            print('Should Be Default Address')

            incmoing_default_status = 'on'


        try:

            new_delivery_address = UserDeliveryAddress.objects.create(user=request.user,address=incoming_address,is_default=True if incmoing_default_status=='on' else False)

            return Response("Created",status=status.HTTP_200_OK)

        except Exception as e:

            return Response(f'{e}',status=status.HTTP_400_BAD_REQUEST)




class DeleteUserAddress(APIView):

    def post(self, request):

        incoming_address_id = request.data.get("address_ID",None)

        try:

            UserDeliveryAddress.objects.get(id=incoming_address_id).delete()

            if UserDeliveryAddress.objects.filter(user=request.user).count() == 1:

                last_delivery_address = UserDeliveryAddress.objects.filter(user=request.user)[0]

                last_delivery_address.is_default = True
                
                last_delivery_address.save()

            return Response("User Address Deleted Successfully",status=status.HTTP_200_OK)

        except (UserDeliveryAddress.DoesNotExist, ValidationError):

            return Response("Error Deleting The Address",status=status.HTTP_400_BAD_REQUEST)




class GetSellerDetails(APIView):

    permission_classes = [IsAuthenticated, IsSeller]

    def get(self, request):

        store = SellerStore.objects.get(user=request.user)

        seller_details = {
            "store_id" : f"{store.id}",
            "store_name" : f"{store.store_name}",
            "store_category" : f"{store.store_category}",
            "store_image" : f"{store.store_image if store.store_image and hasattr(store.store_image,'url') else None}",
        }

        return Response(seller_details, status=status.HTTP_200_OK)



class TestCreateProduct(APIView):

    permission_classes = [IsAuthenticated, IsSeller, IsApprovedSeller]

    def post(self, request):

        try:

            store = SellerStore.objects.get(user=request.user)

        except SellerStore.DoesNotExist:

            return Response("Store Doesn't Exists",status=status.HTTP_400_BAD_REQUEST)


        raw_variants = request.data.get("product_variants", "[]")
        variants = json.loads(raw_variants)


        # RETREIVE DATA FROM FRONTEND

        frontend_data = {"product_name" : request.data.get("product_name", None), "product_subcategory": request.data.get("product_subcategory", None), "product_description": request.data.get("product_description", None), "product_keywords" : request.data.get("product_keywords", None), "product_variants" : variants}

        for field,value in frontend_data.items():

            if value is None or re.match(r"^$|^ $", value):

                return Response(f"Enter Correct Data For {field}", status=status.HTTP_400_BAD_REQUEST)
            

       
        if len(frontend_data.get('product_keywords')) < 5:

            return Response(f"Please Enter 5 Keywords For Your Product",status=status.HTTP_400_BAD_REQUEST)
        
        processed_keywords = ",".join(i for i in frontend_data.get('product_keywords'))



        for idx, variant in enumerate(frontend_data["product_variants"]):

             images = request.FILES.getlist(f"variant_{idx}_image")

             for file in images:

                check_result = check_image_exploitation(image=file)

                if not check_result[0]:

                    return Response(check_result[1], status=status.HTTP_406_NOT_ACCEPTABLE)
                
        
        try:
            with transaction.atomic():
                product = Product.objects.create(
                    product_store=store,
                    product_name=frontend_data["product_name"],
                    product_description=frontend_data['product_description'],
                    product_keywords=processed_keywords,
                    product_sub_category=frontend_data['product_subcategory']
                    )

                for idx, variant_data in enumerate(variants):
                    new_variant = ProductVariant.objects.create(
                        product=product,
                        variant_name=variant_data['name'],
                        variant_price=variant_data['price'],
                        variant_quantity=variant_data['quantity']
                    )

                    # pull actual uploaded files
                    files = request.FILES.getlist(f"variant_{idx}_image")
                    if not files:
                        raise ValidationError(f"No images provided for variant #{idx+1}")

                    for file in files:
                        ok, msg = check_image_exploitation(image=file)
                        if not ok:
                            raise ValidationError(msg)
                        VariantImage.objects.create(
                            variant=new_variant,
                            variant_image=file
                        )

        except ValidationError as ve:
            return Response(str(ve), status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError:
            return Response(
                f"The Product '{frontend_data['product_name']}' Already Exists In Your Store",
                status=status.HTTP_400_BAD_REQUEST
            )






class CreateProduct(APIView):

    permission_classes = [IsAuthenticated, IsSeller, IsApprovedSeller]

    def post(self, request):

        try:

            store = SellerStore.objects.get(user=request.user)

        except SellerStore.DoesNotExist:

            return Response("Store Doesn't Exists",status=status.HTTP_400_BAD_REQUEST)


        # RETREIVE DATA FROM FRONTEND

        frontend_data = {"product_name" : request.data.get("product_name",None), "product_subcategory" : request.data.get('product_subcategory',None) , "product_price" : request.data.get("product_price",None), "product_quantity" : request.data.get("product_quantity", None) , "product_description" : request.data.get("product_description",None), "uploaded_images" : request.FILES.getlist("product_image",None), "product_keywords" : request.data.get('product_keywords',None), "variant_names" : request.data.getlist('variant_name'), "variant_images" : request.FILES.getlist('variant_image')}

        
        # VALIDATE THE FIELDS

        fields_validation = check_frontend_fields(fields=frontend_data)

        
        if not fields_validation[0]:

            return Response({fields_validation[2]}, status=status.HTTP_400_BAD_REQUEST)

        
        
        # COMPRESS THE IMAGES


        compresseed_images = []
        variant_compresseed_images = []

        
        for image in frontend_data.get('uploaded_images'):
            
            compresseed_images.append(compress_image(image=image))
        
        
        
        for v_image in frontend_data.get('variant_images'):
            
            variant_compresseed_images.append(compress_image(image=v_image))

        
        # UPDATE THE ORIGINAL WITH COMPRESSED

        
        frontend_data.update({"uploaded_images":compresseed_images})
        frontend_data.update({"variant_images":variant_compresseed_images})


        # CHECK IMAGES EXPLOITATION

        for img in frontend_data.get('uploaded_images'):

            check_result = check_image_exploitation(image=img)

            if not check_result[0]:

                return Response(check_result[1],status=status.HTTP_406_NOT_ACCEPTABLE)

        
        # VARIANT IMAGES CHECK
        
        for v_img in frontend_data.get('variant_images'):

            v_check_result = check_image_exploitation(image=v_img)

            if not v_check_result[0]:

                return Response(v_check_result[1],status=status.HTTP_406_NOT_ACCEPTABLE)
            


        if len([keyword for keyword in str(frontend_data.get('product_keywords')).split(",") if keyword.strip()]) < 5:

            if len(str(frontend_data.get('product_keywords')).split(",")) == 1:

                return Response("Please Enter Comma Seperated Keywords",status=status.HTTP_400_BAD_REQUEST)

            return Response(f"Please Enter 5 Valid Comma Seperated Keywords For Your Product",status=status.HTTP_400_BAD_REQUEST)

        
        processed_keywords = ",".join(i for i in str(frontend_data.get('product_keywords')).split(","))

        # CREATE THE PRODUCT

        try:
    
            product = Product.objects.create(
                product_store = store,
                product_quantity = frontend_data.get('product_quantity'),
                product_name = frontend_data.get('product_name'),
                product_price = int(frontend_data.get("product_price")),
                product_description = frontend_data.get('product_description'),
                product_sub_category = frontend_data.get('product_subcategory'),
                product_keywords = processed_keywords
                )
        
        except IntegrityError as e:

            return Response(f"The Product '{frontend_data.get('product_name')}' Already Exists In Your Store",status=status.HTTP_400_BAD_REQUEST)

        for image in frontend_data.get('uploaded_images'):

            ProductImage.objects.create(product=product,image=image)
        
        
        try:
            
            for vimg, vname in zip(frontend_data.get('variant_images'),frontend_data.get('variant_names')):

                ProductVariant.objects.create(product=product, variant_name=vname, variant_image=vimg)

        except IntegrityError:

            return Response("No Duplicate Variants Can Be Created", status=status.HTTP_400_BAD_REQUEST)

        
        # RETURN THE RESPONSE

        return Response(f"Product '{product.product_name}' Is Created Successfully",status=status.HTTP_200_OK)




class GetAllProducts(APIView):


    def get(self, request):

        access_token = request.COOKIES.get("access", None)

        if access_token is not None:

            user = get_user_from_token(token=access_token)

        else:

            user = None

        products = Product.objects.all().order_by("?")

        paginator = PageNumberPagination()
        paginator.page_size = 10

        paginated_products = paginator.paginate_queryset(products, request=request)

        serializer = ProductSerializer(paginated_products, many=True, context = {'authenticated_user' : user})

        return paginator.get_paginated_response(serializer.data)



class GetCategoryProducts(APIView):

    def get(self, request, product_category):

        access_token = request.COOKIES.get("access", None)

        if access_token is not None:

            user = get_user_from_token(token=access_token)

        else:

            user = None

        SOLD_WEIGHT = 0.3
        RATING_WEIGHT = 0.2

        products = Product.objects.annotate(
                
                avg_rating=Avg('product_reviews__review_rating')

            ).annotate(

                composite_score=ExpressionWrapper(
                    
                    SOLD_WEIGHT * F('sold_count') +
                    RATING_WEIGHT * Coalesce(F('avg_rating'), Value(0)),
                    output_field=FloatField()
                )

            ).filter(product_sub_category=product_category).order_by("-composite_score")

        paginator = PageNumberPagination()
        paginator.page_size = 15

        paginated_products = paginator.paginate_queryset(products, request=request)

        serializer = ProductSerializer(paginated_products, many=True, context = {'authenticated_user' : user})

        return paginator.get_paginated_response(serializer.data)



class GetProductDetails(APIView):

    def post(self, request):

        id = request.data.get("product_id",None)

        if id is None:

            return Response("Product ID Must Be Provided", status=status.HTTP_400_BAD_REQUEST)

        try:

            product = Product.objects.get(id=id)
            
        
        except (Product.DoesNotExist, ValidationError):

            return Response("This Product Isn't Available",status=status.HTTP_404_NOT_FOUND)
        
        serializer = ProductSerializer(product)


        return Response(serializer.data,status=status.HTTP_200_OK)



class GetSubCategoriesFromParent(APIView):

    permission_classes = [IsAuthenticated, IsSeller, IsApprovedSeller]

    def get(self, request):

        try:

            seller_store = SellerStore.objects.get(user=request.user)

            store_cateogry = seller_store.store_category

            sub_categories = extract_sub_categories_from_parent(parent_name=store_cateogry)

            return Response(sub_categories,status=status.HTTP_200_OK)

        except Exception as e:

            return Response(f'{e}',status=status.HTTP_400_BAD_REQUEST)

    


class ModifyProduct(APIView):

    permission_classes = [IsAuthenticated, IsSeller, IsApprovedSeller]


    def put(self, request, id):
        
        try:
            product = Product.objects.get(id=id)
        except (Product.DoesNotExist, ValidationError):
            return Response("Product Not Found", status=status.HTTP_404_NOT_FOUND)

        # Retrieve data from frontend
        frontend_data = {
            "product_name": request.data.get("product_name", product.product_name),
            "product_price": str(request.data.get("product_price", product.product_price)),
            "product_quantity": str(request.data.get("product_quantity", product.product_quantity)),
            "product_description": request.data.get("product_description", product.product_description),
            "uploaded_images": request.FILES.getlist("product_image"),
        }

        # Validate fields
        fields_validation = check_frontend_fields(fields=frontend_data)
        if not fields_validation[0]:
            return Response({fields_validation[1]: fields_validation[2]}, status=status.HTTP_400_BAD_REQUEST)

        # Process images if provided
        if frontend_data["uploaded_images"]:
            try:
                for image in frontend_data["uploaded_images"]:
                    result = check_image_exploitation(image)
                    if not result[0]:
                        return Response(result[1], status=status.HTTP_400_BAD_REQUEST)
                # Replace old images
                product.product_images.all().delete()
                for image in frontend_data["uploaded_images"]:
                    ProductImage.objects.create(product=product, image=image)
            except Exception as e:
                return Response({"error": f"Image processing error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Update fields if changed
        if frontend_data["product_name"] != product.product_name:
            product.product_name = frontend_data["product_name"]
        if frontend_data["product_price"] != product.product_price:
            product.product_price = frontend_data["product_price"]
        if frontend_data["product_quantity"] != product.product_quantity:
            product.product_quantity = frontend_data["product_quantity"]
        if frontend_data["product_description"] != product.product_description:
            product.product_description = frontend_data["product_description"]

        # Save updated product
        try:
            product.save()
        except IntegrityError:
            return Response(f"Product Name '{frontend_data['product_name']}' Already Exists", status=status.HTTP_400_BAD_REQUEST)

        serializer = ProductSerializer(product)
        return Response(serializer.data, status=status.HTTP_200_OK)




    def delete(self, request, id):

        try:

            product = Product.objects.get(id=id)

        except (Product.DoesNotExist, ValidationError):

            return Response("Product Not Found",status=status.HTTP_404_NOT_FOUND)

        
        try:

            product_name = product.product_name
            product.delete()

            return Response(f"Product {product_name} is Deleted", status=status.HTTP_200_OK)

        except Exception as e:

            return Response(f"{str(e)}",status=status.HTTP_400_BAD_REQUEST)




class GetStoreProducts(APIView):


    def post(self, request):

        store_id = request.data.get("store_id",None)

        if store_id is None:

            return Response("Store ID Must Be Provided", status=status.HTTP_400_BAD_REQUEST)

        try:

            store = SellerStore.objects.get(id=store_id)

            all_store_products = store.store_products

            serializer = ProductSerializer(all_store_products, many=True)

        except (SellerStore.DoesNotExist, ValidationError):

            return Response("Invalid Store ID",status=status.HTTP_400_BAD_REQUEST)
        

        return Response(serializer.data, status=status.HTTP_200_OK)




class ProductsSearchView(APIView):
    

     def get(self, request, search_word):

        access_token = request.COOKIES.get("access", None)

        user = get_user_from_token(token=access_token) if access_token else None

        SEARCH_WEIGHT = 1.0
        SOLD_WEIGHT = 0.1
        RATING_WEIGHT = 0.2

        if search_word and search_word.strip():

            search_query = SearchQuery(search_word)

            search_products = Product.objects.annotate(

                rank=SearchRank(F("search_vector"), search_query),
                avg_rating=Avg('product_reviews__review_rating')

            ).annotate(

                composite_score=ExpressionWrapper(
                    SEARCH_WEIGHT * F('rank') +
                    SOLD_WEIGHT * F('sold_count') +
                    RATING_WEIGHT * Coalesce(F('avg_rating'), Value(0)),
                    output_field=FloatField()
                )

            ).filter(search_vector=search_query).order_by("-composite_score")
            

        else:
            
            search_products = Product.objects.all()

        paginator = PageNumberPagination()
        paginator.page_size = 15
        paginated_products = paginator.paginate_queryset(search_products, request)

        serializer = ProductSerializer(paginated_products, many=True, context={'authenticated_user': user})
        
        return paginator.get_paginated_response(serializer.data)




class AddProductReview(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        product_id = request.data.get("product_id",None)

        if product_id is None:

            return Response("Product ID Must Be Provided",status=status.HTTP_400_BAD_REQUEST)

        # ------------------------- HANDLE FRONTEND DATA -----------------------------

        if not request.data:

            return Response("No Data Was Provided",status=status.HTTP_400_BAD_REQUEST)
        
        
        # ------------------------ RETREIVE PRODUCT ----------------------------------


        try:

            product = Product.objects.get(id=product_id)

        except (Product.DoesNotExist, ValidationError):

            return Response("Product Not Found", status=status.HTTP_404_NOT_FOUND)
        
        

        # -------------------------- CHECK IF USER ALREADY REVIEWED THE PRODUCT -----------------------


        if ProductReview.objects.filter(user=request.user, product=product).exists():

            return Response("You've Already Reviewed This Product",status=status.HTTP_400_BAD_REQUEST)
        


        # --------------------------- OPERATING THE FRONTEND DATA --------------------------------------
        
        
        frontend_data = {"review_text":request.data.get("review_text",None), "review_rating" : request.data.get("review_rating"), "uploaded_images" : request.FILES.getlist('review_image',None)}


        fields_validation = check_frontend_fields(frontend_data)


        if not fields_validation[0]:

            return Response({f"{fields_validation[1]}":f"{fields_validation[2]}"}, status=status.HTTP_400_BAD_REQUEST)
        

        if int(frontend_data.get("review_rating")) < 1 or int(frontend_data.get("review_rating")) > 5:

            return Response({"review_rating":"Enter a Value from 1 to 5"},status=status.HTTP_400_BAD_REQUEST)


        compressed_images = []

        for image in frontend_data.get('uploaded_images'):

            compressed_images.append(compress_image(image=image))


        frontend_data.update({"uploaded_images":compressed_images})


        for img in frontend_data.get("uploaded_images"):

            exploitation_result = check_image_exploitation(image=img)

            if not exploitation_result[0]:

                return Response(f"{exploitation_result[1]}")
            
        
        # ---------------------- CREATING THE REVIEW  -----------------------------

        try:

            review = ProductReview.objects.create(
                user = request.user,
                product = product,
                review_text = frontend_data.get("review_text"),
                review_rating = frontend_data.get("review_rating")
            )


            for review_image in frontend_data.get("uploaded_images"):

                ReviewImage.objects.create(
                    review=review,
                    image=image
                )


            return Response(f"Review for {product.product_name} Created",status=status.HTTP_201_CREATED)
        

        except IntegrityError:

            return Response("You've Already Reviewed This Product", status=status.HTTP_400_BAD_REQUEST)




class GetProductReviews(APIView):

    def get(self, request):

        product_id = request.data.get("product_id",None)

        if product_id is None:

            return Response("Product ID Must Be Provided",status=status.HTTP_400_BAD_REQUEST)

        try:

            product = Product.objects.get(id=product_id)

        except (Product.DoesNotExist, ValidationError):

            return Response("Product Not Found", status=status.HTTP_404_NOT_FOUND)
        

        product_reviews = product.product_reviews.all()


        serializer = ReviewSerializer(product_reviews, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)




class AddModifyCartProduct(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        product_id = request.data.get("product_id",None)
        product_quantity = request.data.get("product_quantity",None)

        if not product_id:

            return Response("No Product ID was Provided", status=status.HTTP_400_BAD_REQUEST)

        try:

            product = Product.objects.get(id=product_id)

            cart, created = UserCart.objects.get_or_create(user=request.user)

            new_cart_product = CartItem.objects.create(cart=cart, product=product, quantity = int(product_quantity) if product_quantity is not None else 1)

            return Response(f"{new_cart_product.quantity} '{product.product_name}' is Added to {request.user.username}'s Cart")

        except (Product.DoesNotExist, ValidationError):

            return Response("Product Not Found", status=status.HTTP_404_NOT_FOUND)
        
        except IntegrityError:

            return Response(f"{product.product_name} from '{product.product_store.store_name}' is Already In {request.user.username}'s Cart", status = status.HTTP_400_BAD_REQUEST)


    def put(self, request):

        product_id = request.data.get("product_id",None)
        product_quantity = request.data.get("product_quantity",None)

        if product_id is None or product_quantity is None:

            return Response("Product ID and Product Quantity Must Be Provided", status=status.HTTP_400_BAD_REQUEST)

        try:

            product = Product.objects.get(id=product_id)

            cart = UserCart.objects.get(user=request.user)

            cart_product = CartItem.objects.get(cart = cart, product = product)

            cart_product.quantity = product_quantity

            cart_product.save()

            return Response(f"{request.user.username}'s Cart Product '{cart_product.product.product_name}'s' Quantity set to {cart_product.quantity}",status=status.HTTP_200_OK)


        except (Product.DoesNotExist, ValidationError):

            return Response("Product Not Found", status=status.HTTP_404_NOT_FOUND)


    def delete(self, request):

        product_id = request.data.get("product_id",None)

        if product_id is None:

            return Response("Product ID Must Be Provided", status=status.HTTP_400_BAD_REQUEST)

        try:

            product = Product.objects.get(id=product_id)

            cart = UserCart.objects.get(user = request.user)

            cart_product = CartItem.objects.get(cart = cart, product = product)

            cart_product.delete()

            return Response(f"{product.product_name} from '{product.product_store.store_name}' is Deleted From {request.user.username}'s Cart", status=status.HTTP_200_OK)

        except (Product.DoesNotExist, ValidationError):

            return Response("Product Not Found", status=status.HTTP_404_NOT_FOUND)




class GetUserCartProducts(APIView):


    permission_classes = [IsAuthenticated]


    def get(self, request):
        

        user_cart = UserCart.objects.get(user = request.user)

        cart_items = CartItem.objects.filter(cart = user_cart)

        serializer = CartItemSerializer(cart_items, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)




class ClearUserCart(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        user = request.user

        try:

            user.user_cart.cart_items.all().delete()

            return Response("Operation Successfull",status=status.HTTP_200_OK)

        except Exception as e:

            return Response(f"{e}",status=status.HTTP_400_BAD_REQUEST)




class CreateUserCartOrder(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        cart = UserCart.objects.get(user = request.user)

        cart_items = cart.cart_items.all()

        # ------------------- CREATE USER ORDER -----------------------

        order = UserOrder.objects.create(user = request.user)

        for i in range(0, len(cart_items)):

            UserOrderItem.objects.create(order = order, product = cart_items[i].product, product_quantity = cart_items[i].quantity)

        order.order_total = sum([i.product_quantity * i.product.product_price for i in order.order_items.all()])

        try:

            amount_in_cents = int(float(order.order_total) * 100)

            intent = stripe.PaymentIntent.create(
                amount = amount_in_cents,
                currency = 'pkr',
                payment_method_types=['card'],
                metadata={'order_id' : order.id},
            )

            order.payment_intent_id = intent.id

            order.save()

        except Exception as e:

            return Response(f'{e}',status=status.HTTP_400_BAD_REQUEST)

        order.save()

        # ------------------- CREATE SELLER ORDERS -----------------------

        seller_item_groups = {}

        for cart_item in cart_items:
            seller = cart_item.product.product_store
            if seller not in seller_item_groups:
                seller_item_groups[seller] = []
            seller_item_groups[seller].append(cart_item)

        print(seller_item_groups)

        with transaction.atomic():
            for seller, items in seller_item_groups.items():
                # Create seller order, ensuring unique order creation per seller
                seller_order = SellerOrder.objects.create(seller=seller, order = order)

                for item in items:
                    # Create seller order item, updating quantity if product already exists in this seller order
                    seller_order_item = SellerOrderItem.objects.create(
                        seller_order=seller_order,
                        product=item.product,
                        product_quantity = item.quantity
                    )
                    
                    seller_order_item.save()

                # Calculate and update seller order total after all items are added
                seller_order.order_amount = sum([
                    item.product_quantity * item.product.product_price
                    for item in seller_order.seller_order_items.all()
                ])
                seller_order.save()

        # cart.cart_items.all().delete()
        
        return Response({"order_id" : order.id}, status=status.HTTP_200_OK)




class CreateUserProductOrder(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        product_id = request.data.get("product_id",None)
        
        order_product_quantity = request.data.get("order_product_quantity",None)

        incoming_delivery_address = request.data.get('order_delivery_address',None)

        if product_id is None or order_product_quantity is None or incoming_delivery_address is None:

            return Response('Product ID, Quantity and Delivery Address Must Be Provided', status=status.HTTP_400_BAD_REQUEST)
        
        try:

            product = Product.objects.get(id=product_id)

        except (Product.DoesNotExist, ValidationError):

            return Response("Error Fetching The Product", status=status.HTTP_404_NOT_FOUND)
        

        # --------------------- CREATE USER ORDER -------------------------

        new_user_order = UserOrder.objects.create(user = request.user, delivery_address = incoming_delivery_address)

        UserOrderItem.objects.create(order = new_user_order, product = product, product_quantity = int(order_product_quantity))

        order_total = product.product_price * int(order_product_quantity)

        new_user_order.order_total = order_total
        
        amount_in_cents = int(float(new_user_order.order_total) * 100)

        try:

            intent = stripe.PaymentIntent.create(
                amount=amount_in_cents,
                currency="pkr",
                payment_method_types=['card'],
                metadata={"order_id" : new_user_order.id}
            )

            new_user_order.payment_intent_id = intent.id

            new_user_order.save()


            # ----------------- CREATE ORDER FOR SELLER ------------------------


            new_seller_order = SellerOrder.objects.create(seller = product.product_store, order = new_user_order)

            SellerOrderItem.objects.create(seller_order = new_seller_order , product = product, product_quantity = int(order_product_quantity))

            product.sold_count += order_product_quantity

            product.product_quantity -= order_product_quantity

            product.save()


            return Response({"msg":"Order Created Successfully", "order_id" : new_user_order.id},status=status.HTTP_200_OK)


        except Exception as e:

            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)




class GetUserAllOrders(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        user_orders = request.user.user_orders.all()

        serializer = UserOrderSerializer(user_orders, many=True)

        return Response(serializer.data,status=status.HTTP_200_OK)




class GetUserOrderDetails(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        incoming_id = request.data.get("order_id",None)

        try:

            user_order = UserOrder.objects.get(id=incoming_id)

            serialzier = UserOrderSerializer(user_order)

            return Response(serialzier.data, status=status.HTTP_200_OK)

        except (UserOrder.DoesNotExist, ValidationError):

            return Response("Failed To Fetch Order", status=status.HTTP_400_BAD_REQUEST)
        



class GetUserWishlist(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        wishlist, created = Wishlist.objects.get_or_create(user=request.user)

        serializer = WishlistSerializer(wishlist)

        return Response(serializer.data, status=status.HTTP_200_OK)




class AddRemoveWishlistProduct(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        user_wishlist = Wishlist.objects.get(user=request.user)

        product_id = request.data.get("product_id",None)

        if product_id is None:

            return Response("Product ID Must Be Provided",status=status.HTTP_400_BAD_REQUEST)
        
        try:

            product = Product.objects.get(id=product_id)

        except (Product.DoesNotExist, ValidationError):

            return Response("Unable To Find Product", status=status.HTTP_404_NOT_FOUND)


        if product in user_wishlist.products.all():

            user_wishlist.products.remove(product)

            user_wishlist.save()

            return Response(f"{product.product_name} is Removed From {request.user.username}'s Wishlist", status=status.HTTP_200_OK)

        else:

            user_wishlist.products.add(product)

            user_wishlist.save()

            return Response(f"{product.product_name} is Added To {request.user.username}'s Wishlist", status=status.HTTP_200_OK)




class ValidatePaymentPage(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        order_id = request.data.get("order_id")

        if order_id is not None:

            try:

                order = UserOrder.objects.get(id=order_id)

                if order.is_paid:

                    return Response({"allow_access" : False, "reason" : "Order Is Already Paid"}, status=status.HTTP_400_BAD_REQUEST)
                
                else:

                    return Response({"allow_access" : True, "reason" : "Not Paid Yet"}, status=status.HTTP_200_OK)

            except (UserOrder.DoesNotExist, ValidationError):

                return Response({"allow_access" : False, "reason" : "Failed To Fetch User Order"}, status=status.HTTP_400_BAD_REQUEST)
        
        else:

            return Response({"allow_access" : False, "reason" : "No Order ID Provided"}, status=status.HTTP_400_BAD_REQUEST)




class GetClientSecret(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):
        
        order_id = request.data.get("order_id")

        if not order_id:

            return Response({"error": "Order ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:

            order = UserOrder.objects.get(id=order_id, user=request.user)

            if order.payment_intent_id:

                payment_intent = stripe.PaymentIntent.retrieve(id=order.payment_intent_id)

                return Response({ "client_secret" : payment_intent.client_secret, "amount_to_pay" : order.order_total }, status=status.HTTP_200_OK)

        except UserOrder.DoesNotExist:
            
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)




class MarkOrderAsPaid(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        incoming_order_id = request.data.get("order_id", None)

        try:

            user_order = UserOrder.objects.get(id=incoming_order_id, user=request.user)

            order_items = user_order.order_items.all()

            for order_item in order_items:

                seller_store = SellerStore.objects.get(id=order_item.product.product_store.id)

                current_revenue_month, created = SellerRevenueMonth.objects.get_or_create(seller_store=seller_store,month_name=MonthString(datetime.now().month), month_year = datetime.now().year)

                current_revenue_month.revenue_amount += user_order.order_total

                current_revenue_month.save()


            payment_verified = self.verify_payment(user_order.payment_intent_id)

            if not payment_verified:

                return Response({"error" : "Payment Verification Failed"}, status=status.HTTP_400_BAD_REQUEST)

            user_order.is_paid = True

            user_order.save()

            return Response("OK", status=status.HTTP_200_OK)


        except (UserOrder.DoesNotExist, ValidationError):

            return Response("Error Fetching User's Order", status=status.HTTP_400_BAD_REQUEST)
        
    
    def verify_payment(self, intent_id):

        try:
            payment_intent = stripe.PaymentIntent.retrieve(id=intent_id)

            return payment_intent.status == 'succeeded'
        
        except stripe.error.StripeError:

            return False




class GetSellerAllRevenueMonths(APIView):

    def post(self, request):

        store_id = request.data.get("store_id", None)
        get_all = request.data.get('get_all', None)

        try:

            seller_store = SellerStore.objects.get(id=store_id)

            if get_all:

                all_months = SellerRevenueMonth.objects.filter(seller_store=seller_store).order_by('-created')

            else:
                
                if SellerRevenueMonth.objects.filter(seller_store=seller_store).order_by('-created').count() > 8:

                    all_months = SellerRevenueMonth.objects.filter(seller_store=seller_store).order_by('-created')[:8]
                
                else:

                    all_months = SellerRevenueMonth.objects.filter(seller_store=seller_store).order_by('-created')




            # Pass `many=True` to handle a queryset
            serializer = RevenueMonthSerializer(all_months, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except SellerStore.DoesNotExist:
            return Response("Seller store not found", status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)



class GetSellerAllOrders(APIView):

    permission_classes = [IsAuthenticated, IsSeller, IsApprovedSeller]

    def get(self, request):

        seller_store = SellerStore.objects.get(user=request.user)

        seller_orders = seller_store.seller_orders.all()

        serializer = SellerOrderSerializer(seller_orders, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)





class GetSellerDashboardDetails(APIView):

    def post(self, request):

        store_id = request.data.get("store_id",None)

        try:

            seller_store = SellerStore.objects.get(id=store_id)

            store_products_count = seller_store.store_products.all().count()

            current_month_revenue, created = SellerRevenueMonth.objects.get_or_create(seller_store = seller_store, month_name = MonthString(datetime.now().month), month_year = datetime.now().year)

            serializer = RevenueMonthSerializer(current_month_revenue)

            return Response({"store_products_count" : store_products_count, "current_revenue_data" : serializer.data}, status=status.HTTP_200_OK)

        except SellerStore.DoesNotExist:

            return Response('Store ID Is Not Provided', status=status.HTTP_404_NOT_FOUND)




def check_frontend_fields(fields : dict) -> list:

    for field,value in fields.items():

        if field == "uploaded_images":

            if value is None or len(value) < 1 or len(value) > 3:

                return [False, field, "Enter At 1 - 3 Images"]
            
            for img in value:

                try:

                    image = Image.open(img)
                    image.verify()

                except (IOError, SyntaxError) as e:

                    return [False, field, "File Isn't An Actual Image"]


            continue

        if value is None or re.match(r"^$|^ $", value):

            return [False, field, "Enter Correct Data"]
        
    return [True, "Everything Is OK"]




def compress_image(image):
    
    # Open the image
    img = Image.open(image)

    # Resize the image while maintaining the aspect ratio
    max_size = (500, 500)
    img.thumbnail(max_size)

    # Save the resized image to memory (BytesIO)
    output = BytesIO()
    img_format = 'JPEG' if img.format == 'JPEG' else 'PNG'  # Adjust format based on the input
    img.save(output, format=img_format, quality=85)  # Adjust quality if needed
    output.seek(0)


    # Create an InMemoryUploadedFile object
    compressed_image = InMemoryUploadedFile(
        output,              # File-like object
        'ImageField',        # Field name
        image.name,          # Image name
        f'image/{img_format.lower()}',  # MIME type
        sys.getsizeof(output),   # Size of the file
        None  # Optional content_type
    )

    return compressed_image




def check_image_exploitation(image) -> list:

    params = {
        'models': 'nudity-2.1',
        'api_user': f'{settings.SIGHTENGINE_USER}',
        'api_secret': f'{settings.SIGHTENGINE_API_SECRET}'
    }

    files = {'media': image}

    print("Starting Image Exploitation Check Request")
    
    r = requests.post('https://api.sightengine.com/1.0/check.json', files=files ,  data=params)

    print("Started Image Exploitation Check Request")

    output = json.loads(r.text)

    print("Test Complete")

    sexual_activity = output['nudity']['sexual_activity']
    sexual_display = output['nudity']['sexual_display']
    very_suggestive = output['nudity']['very_suggestive']
    erotica = output['nudity']['erotica']

    if very_suggestive < 0.99 and sexual_activity <= 0.01 and sexual_display <= 0.01 and erotica <= 0.01:

        return [True, "Images Are OK", sexual_activity, sexual_display, very_suggestive, erotica]

    else:

        return [False, "Images Contain Explicit Content", sexual_activity, sexual_display, very_suggestive, erotica]
    



def process_test_payment(amount : int):

    if not amount:
            
        return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)
    

    stripe.api_key = settings.STRIPE_TEST_KEY

    try:

        charge = stripe.Charge.create(
            amount=int(amount * 100),  # Convert dollars to cents
            currency="usd",
            source="tok_visa",  # Use test token instead of card details
            description="The Amount For The Test Order",
        )

        
        return Response({"message":"Payment Successful", "charge" : charge}, status=status.HTTP_200_OK)
    
    except stripe.error.CardError as e:

        return Response({"Card Error" : str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:

        return Response({"error" : str(e)}, status=status.HTTP_400_BAD_REQUEST)
    



def process_production_payment(amount : int):

    if not amount:

        return Response({"error": "Amount is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Convert dollars to cents
    amount_in_cents = int(float(amount) * 100)


    try:

        # Create a PaymentIntent
        intent = stripe.PaymentIntent.create(

            amount=amount_in_cents,

            currency="usd",

            payment_method_types=["card"],  # Limiting to card payments

        )

        return Response({"client_secret": intent.client_secret}, status=status.HTTP_200_OK)

    except Exception as e:

        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    



def MonthString(month: int) -> str:
    
    months = ['Invalid Month Number','January','February','March','April','May','June','July','August','September','October','November','December']

    return months[month] if 1 <= month <= 12 else months[0]




def get_user_from_token(token : str) -> User:

    
    """
    Extracts The User Object By The Access Token Provided
    """
    
    try:
        
        decoded_token = UntypedToken(token=token)

        user_id = decoded_token.payload.get("user_id")

        try:

            user = User.objects.get(id=user_id)

            return user
        
        except User.DoesNotExist:

            return None

    except (InvalidToken, TokenError) as e:

        return None
    



def extract_sub_categories_from_parent(parent_name : str) -> dict:

    match parent_name:

        case 'electronics':

            return {'parent_category':'Electronics', 'sub_categories' : ['Accessories & Supplies','Camera & Photo','Car & Vehicle Electronics','Cell Phones & Accessories','Computer Accessories','GPS & Navigation','Headphones','Home Audio','Office Electronics','Portable Video & Audio','Security & Survelliance','Television & Audio']}

        case 'fashion':

            return {'parent_category':'Fashion & Clothing', 'sub_categories' : ['Clothes - Women','Handbags - Women','Shoes - Women','Watches - Women','Accessories - Women','Clothing - Men','Watches - Men','Shoes - Men','Accessories - Men','Clothes - Children','Accessories - Children','Shoes - Children']}

        case 'beauty':

            return {'parent_category': 'Beauty & Personal Care', 'sub_categories': ['Makeup','Skin Care','Hair Care','Fragrance - Men','Fragrance - Women','Foot, Hand & Nail Care','Beauty Tools','Shave & Hair Removal','Personal Care - Men','Personal Care - Women','Baby Care','Oral Care']}

        case 'home':

            return {'parent_category':'Home & Kitchen', 'sub_categories': ['Kitchen & Dining','Bedding','Bath','Event & Party','Heating, Cooling & Air Quality','Irons & Steamers','Vaccums & Floor Care','Storage & Organization','Cleaning Supplies','Kitchen Accessories','Cutlery']}

        case 'sports':

            return {'parent_category':'Sports & Outdoors', 'sub_categories' : ['Accessories & Supplies','Camera & Photo','Car & Vehicle Electronics','Cell Phones & Accessories','Computer Accessories','GPS & Navigation','Headphones','Home Audio','Office Electronics','Portable Video & Audio','Security & Survelliance','Television & Audio']}

        case 'books':

            return {'parent_category':'Books & Stationery', 'sub_categories' : ['Accessories & Supplies','Camera & Photo','Car & Vehicle Electronics','Cell Phones & Accessories','Computer Accessories','GPS & Navigation','Headphones','Home Audio','Office Electronics','Portable Video & Audio','Security & Survelliance','Television & Audio']}

        case 'health':

            return {'parent_category':'Health & Wellness', 'sub_categories': ['Health Care','Medical Accessories','Medial Supplies','First Aid Accessories','Nutrition','Vision Care','Vitamns','Dietry Suppliments','Wellness','Relaxation','Exercise Equipments']}

        case 'toys':

            return {'parent_category':'Toys & Games', 'sub_categories': ['Action Figures & Statues','Arts & Crafts','Baby & Toddler Toys','Building Toys','Dolls & Accessories','Dress Up & Pretend Play','Kids Electronics','Games','Grown-Up Toys','Hobbies','Puzzles','Tricycles, Scooters & Wagons','Video Games','RC Toys']}

        case 'automotive':

            return {'parent_category':'Automotive', 'sub_categories': ['Car Care','Car Electronics & Accessories','Exterior Accessories','Interior Accessories','Lights & Lighting Accessories','Motorcycle & Powersports','Oils & Fluids','Paint & Paint Supplies','Performane Parts & Accessories','Replacement Parts','RV Parts & Accessories','Tires & Wheels','Tools & Equipment']}

        case 'jewelry':

            return {'parent_category':'Jewelry & Accessories', 'sub_categories' : ['Accessories & Supplies','Camera & Photo','Car & Vehicle Electronics','Cell Phones & Accessories','Computer Accessories','GPS & Navigation','Headphones','Home Audio','Office Electronics','Portable Video & Audio','Security & Survelliance','Television & Audio']}

        case 'grocery':

            return {'parent_category':'Grocery & Food', 'sub_categories' : ['Accessories & Supplies','Camera & Photo','Car & Vehicle Electronics','Cell Phones & Accessories','Computer Accessories','GPS & Navigation','Headphones','Home Audio','Office Electronics','Portable Video & Audio','Security & Survelliance','Television & Audio']}

        case 'baby':

            return {'parent_category':'Baby Products', 'sub_categories' : ['Accessories & Supplies','Camera & Photo','Car & Vehicle Electronics','Cell Phones & Accessories','Computer Accessories','GPS & Navigation','Headphones','Home Audio','Office Electronics','Portable Video & Audio','Security & Survelliance','Television & Audio']}

        case 'furniture':

            return {'parent_category':'Furniture & Decor', 'sub_categories' : ['Sofas','Dining Tables','Chairs','Armchairs','Curtains','Carpets & Rugs','Tables','Bookcases','Benches','Cabinets','Wardrobe','Desks']}

        case 'pet':

            return {'parent_category':'Pet Supplies', 'sub_categories' : ['Accessories & Supplies','Camera & Photo','Car & Vehicle Electronics','Cell Phones & Accessories','Computer Accessories','GPS & Navigation','Headphones','Home Audio','Office Electronics','Portable Video & Audio','Security & Survelliance','Television & Audio']}

        case 'office':

            return {'parent_category':'Office Supplies',  'sub_categories': ['Filing & Organization','General Office Supplies','Office Equipment','Presentation Supplies','Paper Handling','Name Plates','Shipping Supplies','Office Instruments','Impulse Sealers','Book Accessories','Office Stamps']}

        case _ :

            return {'error' : f"No Such Category Like {parent_name}"}