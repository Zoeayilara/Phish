from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('inbox/', views.inbox, name='inbox'),
    path('email/<int:pk>/', views.email_detail, name='email_detail'),
    path('analytics/', views.analytics, name='analytics'),
    path('settings/', views.settings_view, name='settings'),
    path('scan/', views.scan_email, name='scan_email'),

    # API endpoints
    path('api/stats/', views.api_stats, name='api_stats'),
    path('api/scan/', views.api_scan, name='api_scan'),
    path('api/recent-alerts/', views.api_recent_alerts, name='api_recent_alerts'),
]
