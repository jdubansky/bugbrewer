from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'assets', AssetViewSet)
router.register(r'scans', ScanViewSet)

urlpatterns = [
    path('', index_view, name='index'), 
    path('api/', include(router.urls)),  # Include API paths under /api/
    path('bulk-add/', bulk_asset_view, name='bulk-asset-view'),
    path('bulk-add/success/', bulk_asset_success_view, name='bulk-asset-success'),
    path('modules/', module_list_view, name='module-list'),
    path('modules/add/', add_module_view, name='add-module'),
    path('scan-engine/', scan_engine_view, name='scan-engine'),
    path('scan/cancel/<int:scan_id>/', cancel_scan_view, name='cancel-scan'),
    path('delete-asset/<int:asset_id>/', delete_asset_view, name='delete-asset'),
    path('modules/edit/<int:module_id>/', add_module_view, name='edit-module'),
    path('assets/<int:asset_id>/', asset_detail, name='asset-detail'),
    path('scan/start/<int:asset_id>/', start_scan_view, name='start-scan'),
    path('api/load-yaml-config/<str:filename>', load_yaml_config, name='load-yaml-config'),
    path('asset/<int:asset_id>/cancel-stuck-scans/', cancel_stuck_scans, name='cancel-stuck-scans'),
    path('asset/add/', add_asset, name='add-asset'),
    path('asset/<int:asset_id>/edit/', edit_asset_view, name='edit-asset-view'),
    path('subdomain/<int:pk>/', SubdomainDetailView.as_view(), name='subdomain-detail'),
    path('subdomain/<int:subdomain_id>/scan/', start_subdomain_scan, name='start-subdomain-scan'),
    path('favorites/', favorites_view, name='favorites'),
    path('toggle-favorite/<str:model>/<int:object_id>/', toggle_favorite, name='toggle-favorite'),
    path('tags/', tag_list, name='tag-list'),
    path('ignored-assets/', ignored_assets_view, name='ignored_assets'),
    path('ignored-assets/<int:asset_id>/delete/', delete_ignored_asset, name='delete-ignored-asset'),
    path('continuous-scans/', continuous_scan_list, name='continuous-scan-list'),
    path('continuous-scans/create/', continuous_scan_create, name='continuous-scan-create'),
    path('continuous-scans/<int:scan_id>/', continuous_scan_detail, name='continuous-scan-detail'),
    path('continuous-scans/<int:scan_id>/edit/', continuous_scan_edit, name='continuous-scan-edit'),
    path('continuous-scans/<int:scan_id>/start/', continuous_scan_start, name='continuous-scan-start'),
    path('continuous-scans/<int:scan_id>/pause/', continuous_scan_pause, name='continuous-scan-pause'),
    path('continuous-scans/<int:scan_id>/stop/', continuous_scan_stop, name='continuous-scan-stop'),
]
