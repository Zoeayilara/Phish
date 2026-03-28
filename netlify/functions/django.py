import json
import os
import sys
from urllib.parse import parse_qs

# Add the Django project to the Python path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishguard.settings_production')

import django
django.setup()

from django.core.wsgi import get_wsgi_application
from django.http import JsonResponse

def handler(event, context):
    print("Django Netlify function invoked!")
    print(f"Event: {event}")
    print(f"Context: {context}")
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
            'CONTENT_TYPE': headers.get('content-type', 'text/html'),
            'CONTENT_LENGTH': str(len(body)) if body else '0',
            'wsgi.input': type('', (object,), {'read': lambda self, n: body.encode()})(),
            'wsgi.url_scheme': 'https',
            'SERVER_NAME': 'netlify.app',
            'SERVER_PORT': '443',
            'HTTP_HOST': headers.get('host', 'phishg.netlify.app'),
        }

        # Add headers to environ
        for key, value in headers.items():
            key = key.upper().replace('-', '_')
            if key not in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
                environ[f'HTTP_{key}'] = value

        # Get Django application
        application = get_wsgi_application()

        # Response storage
        response_data = {}

        def start_response(status, response_headers):
            response_data['status'] = status
            response_data['headers'] = dict(response_headers)

        # Call Django
        response = application(environ, start_response)

        # Get response body
        response_body = b''.join(response)

        # Convert headers for Netlify
        netlify_headers = {}
        for key, value in response_data.get('headers', {}).items():
            netlify_headers[key] = value

        # Extract status code
        status_code = int(response_data.get('status', '200 OK').split(' ')[0])

        return {
            'statusCode': status_code,
            'headers': netlify_headers,
            'body': response_body.decode('utf-8')
        }

    except Exception as e:
        print(f"Error in Django function: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'text/html',
            },
            'body': f'<h1>Server Error</h1><p>Error: {str(e)}</p>'
        }
