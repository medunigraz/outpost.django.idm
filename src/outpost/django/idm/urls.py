from django.urls import path

from . import views

app_name = "idm"

urlpatterns = [
    path("passwordcheck/", views.PasswordCheckView.as_view(), name="passwordcheck"),
    path("hooks/account/", views.HookAccountView.as_view(), name="hooks-account"),
]
