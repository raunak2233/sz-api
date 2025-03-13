from django.urls import path
from SpikeZoneApiApp.views import UserLoginView, UserProfileView, UserRegistrationView, ProductView, ProductListView, CategoryView, ProductDetailView
from django.conf import settings
from django.conf.urls.static import static

from django.contrib.staticfiles.urls import staticfiles_urlpatterns
 
urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('uploadCategory/', CategoryView.as_view(), name='category'),
    path('uploadProduct/',
         ProductView.as_view({'post': 'create'}), name='UploadProduct'),
    path('products/', ProductListView.as_view(), name='product-list'),
    path('products/id=<int:pk>/', ProductDetailView.as_view()),

]
# if settings.DEBUG:
#     urlpatterns += static(settings.MEDIA_URL,
#                           document_root=settings.MEDIA_ROOT)

urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
