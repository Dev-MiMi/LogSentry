"""Connect browser addresses to Python view functions."""

from django.urls import path

from . import collected


app_name = "dashboard"
urlpatterns = [
    path("", collected.collected_logs, name="index"),
    path("collected/", collected.collected_logs, name="collected"),
    path("collected/<int:source_id>/", collected.collected_logs, name="collected_source"),
    path("collected/<int:source_id>/alerts/<str:finding_id>/", collected.collected_alert, name="collected_alert"),
]
