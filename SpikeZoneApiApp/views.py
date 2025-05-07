from rest_framework.response import Response
from rest_framework import viewsets, generics, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from rest_framework.views import APIView
from SpikeZoneApiApp.renderers import UserRenderer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from SpikeZoneApiApp.serializers import UserLoginSerializer, GallerySerializer, ContactSerializer, UserProfileSerializer, UserRegistrationSerializer, ProductSerializer, ProductListSerializer, CategorySerializer, OrderItemSerializer, OrderSerializer, AddressSerializer, ReviewSerializer
from SpikeZoneApiApp.models import Products, Review, Gallery, Contact, Category, OrderItem, Address, Order, User
import razorpay
from django.conf import settings
from rest_framework.decorators import action
from django.db import transaction
from rest_framework.exceptions import ValidationError



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
        order = serializer.validated_data['order']  # Get the order from the request

        # Check if the user has placed the order for the product
        if not Order.objects.filter(id=order.id, user=user, items__product=product).exists():
            raise ValidationError("You cannot review this product because you have not placed an order for it.")

        # Check if the user has already reviewed the product for the same order
        if Review.objects.filter(user=user, product=product, order=order).exists():
            raise ValidationError("You have already reviewed this product for this order.")

        # Save the review if all checks pass
        serializer.save(user=user, order=order)

class GalleryViewSet(viewsets.ModelViewSet):
    queryset = Gallery.objects.all()
    serializer_class = GallerySerializer
    parser_classes = [MultiPartParser, FormParser]  # Allow file uploads
    permission_classes = [IsAuthenticatedOrReadOnly]  # Allow public read access, but restrict write access