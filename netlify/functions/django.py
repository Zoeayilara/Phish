import json
import os
import sys

# Add the Django project to the Python path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishguard.settings_production')

import django
django.setup()

from django.http import JsonResponse
from django.core.wsgi import get_wsgi_application

def handler(event, context):
    """
    Netlify function handler for Django
    """
    try:
        # Parse the event
        path = event.get('path', '/')
        method = event.get('httpMethod', 'GET')
        headers = event.get('headers', {})
        body = event.get('body', '')
        query_params = event.get('queryStringParameters', {}) or {}

        # Create Django WSGI environ
        environ = {
            'REQUEST_METHOD': method,
            'PATH_INFO': path,
            'QUERY_STRING': '&'.join([f'{k}={v}' for k, v in query_params.items()]),
            'CONTENT_TYPE': headers.get('content-type', ''),
            'CONTENT_LENGTH': str(len(body)) if body else '0',
            'wsgi.input': body,
            'wsgi.url_scheme': 'https',
            'SERVER_NAME': 'netlify.app',
            'SERVER_PORT': '443',
        }

        # Add headers to environ
        for key, value in headers.items():
            key = key.upper().replace('-', '_')
            if key not in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
                environ[f'HTTP_{key}'] = value

        # Get Django application
        application = get_wsgi_application()

        # Call Django
        def start_response(status, response_headers):
            pass

        response = application(environ, start_response)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
            },
            'body': json.dumps({'message': 'Django function is working'})
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
            },
            'body': json.dumps({'error': str(e)})
        }
