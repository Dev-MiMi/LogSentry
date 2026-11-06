from django.urls import path

from . import views


app_name = "receiver"
urlpatterns = [
    path("receiver/", views.inbox, name="inbox"),
    path("receiver/wazuh-rules/", views.wazuh_rules, name="wazuh_rules"),
    path("receiver/events/<int:record_id>/", views.investigate, name="investigate"),
    path("api/v1/events/", views.ReceiveEvents.as_view(), name="events"),
    path("api/v1/heartbeat/", views.Heartbeat.as_view(), name="heartbeat"),
]
