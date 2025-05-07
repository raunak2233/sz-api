from rest_framework import serializers
from SpikeZoneApiApp.models import User, Products, Gallery, Category, Order, Contact, OrderItem, Address, Review
from django.contrib.auth import authenticate
from django.db import transaction


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
        extra_kwargs = {
            'password': {'write_only': True},
            'name': {'required': True},
            'contact': {'required': True},
            'email': {'required': True},
            'address': {'required': False},
            'state': {'required': False},
            'city': {'required': False},
            'postalcode': {'required': False}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create_user(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=255)


class UserProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'name', 'contact', 'email',
                  'address', 'state', 'city', 'postalcode', 'is_admin']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"

class ReviewSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name', read_only=True)
    product_title = serializers.CharField(source='product.title', read_only=True)
    razorpay_order_id = serializers.CharField(source='order.razorpay_order_id', read_only=True)  # Fetch directly from the order

    class Meta:
        model = Review
        fields = ['id', 'product', 'product_title', 'user', 'user_name', 'order', 'razorpay_order_id', 'rating', 'review_text', 'created_at']
            
class ProductSerializer(serializers.ModelSerializer):

    reviews = ReviewSerializer(many=True, read_only=True)

    class Meta:
        model = Products
        fields = ['id', 'product_sku', 'category', 'reviews', 'inStock', 'isBest', 'title', 'slug', 'image1', 'image2', 'image3', 'image4', 'image5', 'price', 'max_price', 'short_desc', 'long_desc', 'bullet_one', 'bullet_two', 'bullet_three', 'bullet_four', 'bullet_five']


class ProductListSerializer(serializers.ModelSerializer):

    category_name = serializers.CharField(source='category.category_name', read_only=True)

    class Meta:
        model = Products
        fields = ["id", "isBest", "image1", "image2", "image3", "image4", "image5", "title", "price", "max_price", "short_desc", "long_desc",
                  "bullet_one", "slug", "bullet_two", "bullet_three", "bullet_four",'category_id', 'category_name']

            
class OrderItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.title', read_only=True)
    product_price = serializers.CharField(source='product.price', read_only=True)
    product_image = serializers.ImageField(source='product.image1', read_only=True)
    item_total = serializers.SerializerMethodField()
    product = serializers.PrimaryKeyRelatedField(queryset=Products.objects.all())

    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'product_name', 'product_price', 
                 'product_image', 'quantity', 'item_total']

    def get_item_total(self, obj):
        return float(obj.product.price) * obj.quantity

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['id', 'name', 'email', 'subject', 'message', 'created_at']

class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['id', 'full_name', 'phone', 'address', 'city', 'state', 'zip_code']

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True)
    total_amount = serializers.SerializerMethodField()
    order_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    address_details = AddressSerializer(source='address', read_only=True)
    delivery_status_display = serializers.CharField(source='get_delivery_status_display', read_only=True)
    user_details = serializers.SerializerMethodField()  # Add user details for admin users

    class Meta:
        model = Order
        fields = [
            'id', 'user', 'user_details', 'items', 'total_amount',
            'delivery_status', 'payment_status', 'address',
            'razorpay_order_id', 'razorpay_payment_id', 'order_date', 'address_details', 'delivery_status_display'
        ]

    def get_total_amount(self, obj):
        # Dynamically calculate the total amount from the items
        return sum(float(item.product.price) * item.quantity for item in obj.items.all())

    def get_user_details(self, obj):
        # Include user details only if the request is made by an admin
        request = self.context.get('request')
        if request and request.user.is_admin:
            return {
                "id": obj.user.id,
                "name": obj.user.name,
                "email": obj.user.email,
                "contact": obj.user.contact
            }
        return None
    def create(self, validated_data):
        items_data = validated_data.pop('items')
        with transaction.atomic():
            # Create the order first
            order = Order.objects.create(**validated_data)

            # Create only the items provided in the request
            for item_data in items_data:
                OrderItem.objects.create(
                    order=order,
                    product=item_data['product'],  # Use product directly
                    quantity=item_data['quantity']
                )
        return order

    def update(self, instance, validated_data):
        items_data = validated_data.pop('items', None)

        # Update order fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update order items if provided
        if items_data is not None:
            # Clear existing items to avoid duplicates
            instance.items.all().delete()

            # Add new items
            for item_data in items_data:
                OrderItem.objects.create(
                    order=instance,
                    product=item_data['product'],
                    quantity=item_data['quantity']
                )

        return instance
                
class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'

class GallerySerializer(serializers.ModelSerializer):
    class Meta:
        model = Gallery
        fields = ['id', 'image', 'image_title', 'image_description', 'created_at']