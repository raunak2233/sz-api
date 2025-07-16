from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.utils.text import slugify
from django.utils import timezone
import datetime

class CustomUserManager(BaseUserManager):
    def create_user(self, email, name, contact, address="", state="", city="", postalcode="", is_active=True, is_admin=False, password=None):

        if not email:
            raise ValueError('Email Required')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            contact=contact,
            address=address,
            state=state,
            city=city,
            postalcode=postalcode,
        )

        user.set_password(password)
        user.save(using=self.db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='Email', 
        max_length=255,
        unique=True
    )
    name = models.CharField(max_length=50)
    contact = models.CharField(max_length=50)
    address = models.CharField(max_length=999, default='', null=True, blank=True)
    state = models.CharField(max_length=50, default='', null=True, blank=True)
    city = models.CharField(max_length=50, default='', null=True, blank=True)
    postalcode = models.CharField(max_length=10, default='', null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'contact']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin


class Category(models.Model):
    category_id = models.CharField(max_length=50)
    category_name = models.CharField(max_length=50)
 

class Products(models.Model):
    product_sku = models.CharField(max_length=50)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    inStock = models.BooleanField(default=True)
    isBest = models.BooleanField(default=False)
    title = models.CharField(max_length=50)
    slug = models.SlugField(unique=True, max_length=255)  # Slug must be set manually
    image1 = models.ImageField(upload_to="media/", null=True, blank=True)
    image2 = models.ImageField(upload_to="media/", null=True, blank=True)
    image3 = models.ImageField(upload_to="media/", null=True, blank=True)
    image4 = models.ImageField(upload_to="media/", null=True, blank=True)
    image5 = models.ImageField(upload_to="media/", null=True, blank=True)
    price = models.CharField(max_length=50)
    max_price = models.CharField(max_length=50)
    short_desc = models.CharField(max_length=500)
    long_desc = models.CharField(max_length=9999)
    bullet_one = models.CharField(max_length=500)
    bullet_two = models.CharField(max_length=500, null=True, blank=True)
    bullet_three = models.CharField(max_length=500, null=True, blank=True)
    bullet_four = models.CharField(max_length=500, null=True, blank=True)
    bullet_five = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return self.title

class Address(models.Model):
    user = models.ForeignKey(User, related_name='addresses', on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    zip_code = models.CharField(max_length=10)

    def __str__(self):
        return f"Address {self.id} for {self.user.username}"

class Order(models.Model):
    DELIVERY_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled')
    ]
    
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded')
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.ForeignKey(Address, on_delete=models.SET_NULL, null=True)
    pay_method = models.CharField(max_length=255)
    order_date = models.DateTimeField(auto_now_add=True)
    razorpay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    delivery_status = models.CharField(
        max_length=20, 
        choices=DELIVERY_STATUS_CHOICES,
        default='pending'
    )
    payment_status = models.CharField(
        max_length=20, 
        choices=PAYMENT_STATUS_CHOICES,
        default='pending'
    )

    def __str__(self):
        return f"Order {self.id} by {self.user.name} - {self.delivery_status}"
    
    @property
    def total_amount(self):
        return sum(
            float(item.product.price) * item.quantity 
            for item in self.items.all()
        )

    def __str__(self):
        return f"Order {self.id} by {self.user.name} - {self.delivery_status}"

class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name='items', on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.product.title} (x{self.quantity})"

class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=255)
    subject = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Contact from {self.name} - {self.subject}"

class Review(models.Model):
    product = models.ForeignKey(Products, related_name='reviews', on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name='reviews', on_delete=models.CASCADE)
    order = models.ForeignKey(Order, related_name='reviews', on_delete=models.CASCADE)  # Add this field
    rating = models.PositiveIntegerField()
    review_text = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review by {self.user.name} for {self.product.title} - {self.rating} stars"  

class Gallery(models.Model):
    image = models.ImageField(upload_to="gallery/")
    image_title = models.CharField(max_length=255)
    image_description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.image_title    
    
class Blog(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title   

class EmailOTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + datetime.timedelta(minutes=5)

    def __str__(self):
        return f"{self.email} - {self.otp}"     

class Wishlist(models.Model):
    user = models.ForeignKey(User, related_name='wishlists', on_delete=models.CASCADE)
    product = models.ForeignKey(Products, related_name='wishlisted_by', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'product')

    def __str__(self):
        return f"{self.user.email} - {self.product.title}"