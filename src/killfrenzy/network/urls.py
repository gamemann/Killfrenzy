from django.urls import path, include
from .views import *

app_name = "network"

urlpatterns = [
    path('', index, name='index'),
    path('edge/<int:edge_id>', view_edge, name='edge')
]