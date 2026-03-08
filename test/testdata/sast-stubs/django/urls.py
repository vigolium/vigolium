from django.urls import path, re_path
from . import views

urlpatterns = [
    path("users/", views.list_users),
    path("users/create/", views.create_user),
    path("users/<int:pk>/", views.get_user),
    path("users/<int:pk>/update/", views.update_user),
    path("users/<int:pk>/delete/", views.delete_user),
    path("health/", views.health_check),
    path("items/", views.ItemViewSet.as_view({"get": "list", "post": "create"})),
    path("items/<int:pk>/", views.ItemViewSet.as_view({"get": "retrieve", "put": "update"})),
    re_path(r"^search/(?P<query>.+)/$", views.search),
]
