from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from scans.views import register_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('scans.urls')),
    path('login/', auth_views.LoginView.as_view(template_name='auth/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('register/', register_view, name='register'),
]
