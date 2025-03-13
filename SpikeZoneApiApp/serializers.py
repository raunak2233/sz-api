from rest_framework import serializers
from SpikeZoneApiApp.models import User, Products, Category
from django.contrib.auth import authenticate


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
        fields = ['id', 'name', 'contact',
                  'address', 'state', 'city', 'postalcode']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = "__all__"


class ProductListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = ["id", "isBest", "image1", "image2", "image3", "image4", "image5", "title", "price", "max_price", "short_desc", "long_desc",
                  "bullet_one", "bullet_two", "bullet_three", "bullet_four", "bullet_five",]
