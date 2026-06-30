from django.urls import path

from . import views

app_name = "idm"

urlpatterns = [
    path("passwordcheck/", views.PasswordCheckView.as_view(), name="passwordcheck"),
]
