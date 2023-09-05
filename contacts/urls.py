# contacts/urls.py

from django.urls import path
from django.contrib.auth import views as auth_views
from .views import CustomPasswordResetView

from . import views

urlpatterns = [
    path('logout/', views.logout_view, name='logout'),
    # path('login/', views.CustomLoginView.as_view(), name='login'),
    # path('index/', views.user_login, name='login'),
    # path('', views.user_login, name='user_login'),
    path('index/', auth_views.LoginView.as_view(template_name='users/index.html', redirect_authenticated_user=True),name='login'),

    path('signup/', views.signup, name='signup'),

    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('reset_password/', views.reset_password, name='reset_password'),
    
    path('password_reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('reset_password/<str:uidb64>/<str:token>/', views.reset_password, name='reset_password'),
    path('reset_password/<str:uidb64>/<str:token>/', views.reset_password, name='password_reset_confirm'),
    path('reset_password/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_done.html'), name='password_reset_complete'),
    
    path('contact_details/', views.contact_details, name='contact_details'),
    path('search_contact/', views.search_contact, name='search_contact'),
    path('delete_contact/<int:contact_id>/', views.delete_contact, name='delete_contact'),
    
    path('', views.user_login, name='user_login'),
    path('contact_list/', views.contact_list, name='contact_list'),
    path('existing_contact_details/', views.existing_contact_details, name='existing_contact_details'),

]
