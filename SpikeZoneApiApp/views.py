from rest_framework.response import Response
from rest_framework import viewsets, generics, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from rest_framework.views import APIView
from SpikeZoneApiApp.renderers import UserRenderer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from SpikeZoneApiApp.serializers import UserLoginSerializer, EmailSerializer, OTPVerifySerializer, BlogSerializer, GallerySerializer, ContactSerializer, UserProfileSerializer, UserRegistrationSerializer, ProductSerializer, ProductListSerializer, CategorySerializer, OrderItemSerializer, OrderSerializer, AddressSerializer, ReviewSerializer, WishlistSerializer
from SpikeZoneApiApp.models import Products, Review, EmailOTP, Blog, Gallery, Contact, Category, OrderItem, Address, Order, User, Wishlist
import razorpay
import random
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import action
from django.db import transaction
from rest_framework.exceptions import ValidationError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
from django.core.files.storage import default_storage
from rest_framework.viewsets import ModelViewSet
from django.contrib.auth import get_user_model

User = get_user_model()


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_token_for_user(user)
        return Response({'token': token, 'msg': 'You have successfully registered'}, status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_token_for_user(user)
            return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': 'Email/Password is Invalid', 'email': email, 'pass': password}, status=status.HTTP_404_NOT_FOUND)



class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user_id = request.query_params.get('id')

        if user_id:
            if not request.user.is_admin:
                return Response(
                    {"error": "You do not have permission to access this resource."},
                    status=status.HTTP_403_FORBIDDEN
                )

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            user = request.user

        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CategoryView(APIView):
    serializer_class = CategorySerializer

    def get(self, request):
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductView(viewsets.ModelViewSet):
    parser_classes = (MultiPartParser, FormParser)
    queryset = Products.objects.all()
    serializer_class = ProductSerializer

    def create(self, request, *args, **kwargs):
        # Add the user field to the request data
        request.data['user'] = request.user.id

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        return Response({"message": "Product uploaded successfully."}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save()


class ProductListView(generics.ListAPIView):
    queryset = Products.objects.all()
    serializer_class = ProductListSerializer


class ProductDetailBySlugView(generics.RetrieveAPIView):
    queryset = Products.objects.all()
    serializer_class = ProductSerializer
    lookup_field = 'slug'

    def get(self, request, slug, *args, **kwargs):
        product = self.get_object()
        serializer = self.get_serializer(product)
        return Response(serializer.data)

class ProductDetailView(generics.RetrieveAPIView):
    queryset = Products.objects.all()
    serializer_class = ProductSerializer

    def get(self, request, pk, *args, **kwargs):
        product = self.get_object()
        serializer = self.get_serializer(product)
        return Response(serializer.data)    


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()  # Explicitly define the queryset
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initialize Razorpay client with API key and secret
        self.client = razorpay.Client(
            auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
        )

    def get_queryset(self):
        # Check if the authenticated user is an admin
        if self.request.user.is_admin:
            # Admin can see all orders
            return Order.objects.all().select_related('user', 'address').prefetch_related('items', 'items__product')
        else:
            # Regular users can only see their own orders
            return Order.objects.filter(user=self.request.user).select_related('user', 'address').prefetch_related('items', 'items__product')

    def create(self, request, *args, **kwargs):
        try:
            with transaction.atomic():
                # Validate and create the order
                serializer = self.get_serializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                order = serializer.save(user=request.user)  # Automatically associate the order with the logged-in user

                # Calculate the total amount
                order.refresh_from_db()
                amount = int(float(order.total_amount) * 100)  # Convert to paise

                # Create Razorpay order
                razorpay_order = self.client.order.create({
                    "amount": amount,
                    "currency": "INR",
                    "payment_capture": "1",
                    "notes": {
                        "order_id": str(order.id),
                        "user_id": str(order.user.id)
                    }
                })

                # Update the order with Razorpay details
                order.razorpay_order_id = razorpay_order['id']
                order.save()

                # Return the response with updated data
                serializer = self.get_serializer(order)
                response_data = serializer.data
                response_data.update({
                    "razorpay_order_id": razorpay_order['id'],
                    "razorpay_amount": amount,
                    "currency": "INR",
                    "key": settings.RAZORPAY_KEY_ID
                })

                return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Order deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
    
    def list(self, request, *args, **kwargs):
        # Force fresh data fetch
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    @action(detail=True, methods=['patch'])
    def update_status(self, request, pk=None):
        order = self.get_object()
        delivery_status = request.data.get('delivery_status')
        payment_status = request.data.get('payment_status')

        if delivery_status and delivery_status in dict(Order.DELIVERY_STATUS_CHOICES):
            order.delivery_status = delivery_status
        
        if payment_status and payment_status in dict(Order.PAYMENT_STATUS_CHOICES):
            order.payment_status = payment_status

        order.save()
        serializer = self.get_serializer(order)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def verify_payment(self, request, pk=None):
        try:
            order = self.get_object()
            
            # Get the payment details from request
            payment_id = request.data.get('razorpay_payment_id')
            order_id = request.data.get('razorpay_order_id')
            signature = request.data.get('razorpay_signature')

            # Log the received data for debugging
            print(f"Received payment verification data:")
            print(f"Payment ID: {payment_id}")
            print(f"Order ID: {order_id}")
            print(f"Signature: {signature}")

            # Create parameters dict
            params_dict = {
                'razorpay_payment_id': payment_id,
                'razorpay_order_id': order_id,
                'razorpay_signature': signature
            }

            try:
                # Verify signature
                self.client.utility.verify_payment_signature(params_dict)
                
                # Update order status
                order.payment_status = 'completed'
                order.razorpay_payment_id = payment_id
                order.save()

                return Response({
                    'status': 'success',
                    'message': 'Payment verified successfully',
                    'order_id': order.id,
                    'payment_id': payment_id
                })

            except razorpay.errors.SignatureVerificationError as e:
                print(f"Signature verification failed: {str(e)}")
                order.payment_status = 'failed'
                order.save()
                return Response({
                    'status': 'error',
                    'message': 'Payment signature verification failed'
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(f"Payment verification error: {str(e)}")
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
class AddressViewSet(viewsets.ModelViewSet):
    queryset = Address.objects.all()  # Explicitly define the queryset
    serializer_class = AddressSerializer

    def get_queryset(self):
        user_id = self.kwargs.get('user_id')
        if user_id is not None:
            return Address.objects.filter(user_id=user_id)
        return self.queryset

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(
                {"message": "Address deleted successfully"}, 
                status=status.HTTP_204_NO_CONTENT
            )
        except Address.DoesNotExist:
            return Response(
                {"error": "Address not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )

class ProductUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Products.objects.all()
    serializer_class = ProductSerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Product deleted successfully"}, status=status.HTTP_200_OK)

class CategoryUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Category deleted successfully"}, status=status.HTTP_200_OK)

class UserProfileUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer


class ContactViewSet(viewsets.ModelViewSet):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Contact data submitted successfully."}, status=status.HTTP_201_CREATED)
    
class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [IsAuthenticated()]

    def get_queryset(self):
        product_id = self.request.query_params.get('product_id')
        if product_id:
            return Review.objects.filter(product_id=product_id)
        return super().get_queryset()

    def perform_create(self, serializer):
        user = self.request.user
        product = serializer.validated_data['product']

        # If admin, allow review without order
        if user.is_admin:
            serializer.save(user=user, order=None)
            return

        order = serializer.validated_data.get('order')
        if not order:
            raise ValidationError("Order is required to review this product.")

        if not Order.objects.filter(id=order.id, user=user, items__product=product).exists():
            raise ValidationError("You cannot review this product because you have not placed an order for it.")

        if Review.objects.filter(user=user, product=product, order=order).exists():
            raise ValidationError("You have already reviewed this product for this order.")

        serializer.save(user=user, order=order)

class GalleryViewSet(viewsets.ModelViewSet):
    queryset = Gallery.objects.all()
    serializer_class = GallerySerializer
    parser_classes = [MultiPartParser, FormParser]  # Allow file uploads
    permission_classes = [IsAuthenticatedOrReadOnly]  # Allow public read access, but restrict write access


@csrf_exempt
def update_seo_json(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            seo_file_path = os.path.join(settings.BASE_DIR, 'SpikeZoneApiApp', 'media', 'seo.json')

            # Load existing JSON
            with open(seo_file_path, 'r') as f:
                current_data = json.load(f)

            # Merge new data into selected slug
            for slug, values in data.items():
                current_data[slug] = values

            # Write updated JSON back to file
            with open(seo_file_path, 'w') as f:
                json.dump(current_data, f, indent=2)

            return JsonResponse({'message': 'SEO JSON updated successfully'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Only POST allowed'}, status=405)

class BlogImageUploadView(APIView):
    parser_classes = [MultiPartParser]

    def post(self, request, *args, **kwargs):
        file = request.FILES['image']
        filename = default_storage.save(file.name, file)
        image_url = request.build_absolute_uri(default_storage.url(filename))
        return Response({'image_url': image_url})

class BlogViewSet(ModelViewSet):
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer

def generate_otp():
    return str(random.randint(100000, 999999))

class AdminAddReviewView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if not user.is_admin:
            return Response({"error": "Only admin users can add reviews via this endpoint."}, status=status.HTTP_403_FORBIDDEN)

        product_id = request.data.get('product')
        rating = request.data.get('rating')
        review_text = request.data.get('review_text') or request.data.get('review')
        name = request.data.get('name', '')  # <-- Get name from request

        if not (product_id and rating):
            return Response({"error": "Product and rating are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            product = Products.objects.get(id=product_id)
        except Products.DoesNotExist:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)

        review = Review.objects.create(
            product=product,
            user=user,
            rating=rating,
            review_text=review_text or "",
            order=None,
            name=name
        )

        serializer = ReviewSerializer(review)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
class SendOTPView(APIView):
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = generate_otp()

            EmailOTP.objects.create(email=email, otp=otp)

            send_mail(
                subject='One Time Password (OTP) for Email Verification',
                message=f'Your OTP code is {otp}',
                from_email=None,
                recipient_list=[email],
                html_message=f'''
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f9f9f9;">
            <h2 style="color: #333;">🔐 Email Verification</h2>
            <p style="font-size: 16px; color: #555;">
                Hello, <br><br>
                Your One-Time Password (OTP) is:
            </p>
            <div style="font-size: 28px; font-weight: bold; color: #0b5ed7; padding: 10px 0;">
                {otp}
            </div>
            <p style="font-size: 14px; color: #888;">
                This OTP is valid for 5 minutes. Please do not share it with anyone.<br><br>
                Regards,<br>
                <strong>SpikeZone Team</strong>
            </p>
        </div>'''
            )

            return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            try:
                otp_obj = EmailOTP.objects.filter(email=email, otp=otp).latest('created_at')
                if otp_obj.is_expired():
                    return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
                return Response({'message': 'OTP verified successfully'}, status=status.HTTP_200_OK)
            except EmailOTP.DoesNotExist:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 

class WishlistViewSet(viewsets.ModelViewSet):
    serializer_class = WishlistSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Wishlist.objects.filter(user=self.request.user).select_related('product')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    # Override lookup field to be 'product'
    lookup_field = 'product_id'

    def destroy(self, request, *args, **kwargs):
        product_id = kwargs.get('product_id')
        wishlist_item = Wishlist.objects.filter(user=request.user, product_id=product_id).first()
        if wishlist_item:
            wishlist_item.delete()
            return Response({"message": "Removed from wishlist."}, status=status.HTTP_204_NO_CONTENT)
        return Response({"error": "Wishlist item not found."}, status=status.HTTP_404_NOT_FOUND)    