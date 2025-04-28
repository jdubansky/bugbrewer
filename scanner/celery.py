import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bugbrewer.settings')

app = Celery('bugbrewer')

# Load task modules from all registered Django apps.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Autodiscover tasks in installed Django apps
app.autodiscover_tasks()
