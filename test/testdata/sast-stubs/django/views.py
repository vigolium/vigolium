from django.http import JsonResponse
from rest_framework.viewsets import ViewSet
from rest_framework.response import Response


def list_users(request):
    q = request.GET.get("q", "")
    page = request.GET.get("page", "1")
    return JsonResponse({"users": [], "q": q, "page": page})


def create_user(request):
    name = request.POST.get("name")
    email = request.POST.get("email")
    return JsonResponse({"name": name, "email": email})


def get_user(request, pk):
    return JsonResponse({"id": pk})


def update_user(request, pk):
    name = request.data.get("name")
    return JsonResponse({"id": pk, "name": name})


def delete_user(request, pk):
    return JsonResponse({"deleted": pk})


def health_check(request):
    return JsonResponse({"status": "ok"})


def search(request, query):
    results = request.query_params.get("limit", "10")
    return JsonResponse({"query": query, "limit": results})


class ItemViewSet(ViewSet):
    def list(self, request):
        category = request.query_params.get("category")
        return Response({"items": []})

    def create(self, request):
        title = request.data.get("title")
        return Response({"title": title})

    def retrieve(self, request, pk=None):
        return Response({"id": pk})

    def update(self, request, pk=None):
        return Response({"id": pk})
