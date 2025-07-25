from django.urls import path, include
from SpikeZoneApiApp.views import UserLoginView, ContactViewSet, BlogViewSet, GalleryViewSet, UserProfileView, UserRegistrationView, ProductView, ProductListView,  ProductDetailBySlugView, CategoryView, ProductDetailView, ProductUpdateDeleteView, CategoryUpdateDeleteView, UserProfileUpdateDeleteView, OrderViewSet, AddressViewSet, ReviewViewSet, update_seo_json, BlogImageUploadView, SendOTPView, VerifyOTPView, AdminAddReviewView, WishlistViewSet
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter

from django.contrib.staticfiles.urls import staticfiles_urlpatterns

router = DefaultRouter()
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'addresses', AddressViewSet, basename='address')
router.register(r'contact', ContactViewSet, basename='contact')
router.register(r'reviews', ReviewViewSet, basename='review')
router.register(r'gallery', GalleryViewSet, basename='gallery')
router.register(r'blogs', BlogViewSet, basename='blog')
router.register(r'wishlist', WishlistViewSet, basename='wishlist')

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('uploadCategory/', CategoryView.as_view(), name='category'),
    path('uploadProduct/',
         ProductView.as_view({'post': 'create'}), name='UploadProduct'),
    path('products/', ProductListView.as_view(), name='product-list'),
    path('products/update/<int:pk>/', ProductUpdateDeleteView.as_view(), name='product-update-delete'),
    path('categories/update/<int:pk>/', CategoryUpdateDeleteView.as_view(), name='category-update-delete'),
    path('profiles/update/<int:pk>/', UserProfileUpdateDeleteView.as_view(), name='profile-update-delete'),
    path('products/<int:pk>/', ProductDetailView.as_view()),
    path('products/<slug:slug>/', ProductDetailBySlugView.as_view(), name='product-detail-by-slug'),
    path('addresses/<int:user_id>/', AddressViewSet.as_view({
        'get': 'list',
        'delete': 'destroy'
    }), name='user-addresses'),
    path('addresses/delete/<int:pk>/', AddressViewSet.as_view({
        'delete': 'destroy'
    }), name='address-delete'),
    path('orders/<int:pk>/verify_payment/', OrderViewSet.as_view({
        'post': 'verify_payment'
    }), name='verify-payment'),
    path('', include(router.urls)), 
    path('update-seo/', update_seo_json, name='update_seo_json'),
    path("blogUpload/", BlogImageUploadView.as_view()),
    path('send-otp/', SendOTPView.as_view()),
    path('verify-otp/', VerifyOTPView.as_view()),
    path('wishlist/<int:product_id>/', WishlistViewSet.as_view({'delete': 'destroy'}), name='wishlist-delete-by-product'),
    path('admin/add-review/', AdminAddReviewView.as_view(), name='admin-add-review'),








]

urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
