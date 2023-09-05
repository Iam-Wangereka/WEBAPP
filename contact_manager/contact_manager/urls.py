# contact_manager/urls.py

from django.contrib import admin
from django.urls import path, include
import contacts.urls as contacts_urls


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(contacts_urls)),   # Add a URL pattern to call our
    path('reset_password/', include('django.contrib.auth.urls')),
]
