from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

# Create your models here.


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
    category = models.CharField(max_length=100)
    inStock = models.BooleanField(default=True)
    isBest = models.BooleanField(default=False)
    title = models.CharField(max_length=50)
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
