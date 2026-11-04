"""Project URL configuration: pass dashboard URLs to the dashboard app."""

from django.urls import include, path
from django.contrib.auth.views import LoginView, LogoutView


urlpatterns = [
    path("accounts/login/", LoginView.as_view(template_name="receiver/login.html"), name="login"),
    path("accounts/logout/", LogoutView.as_view(), name="logout"),
    path("", include("dashboard.urls")),
    path("", include("receiver.urls")),
]
