from django.urls import path

from . import views


app_name = "receiver"
urlpatterns = [
    path("receiver/", views.inbox, name="inbox"),
    path("api/v1/events/", views.ReceiveEvents.as_view(), name="events"),
]
