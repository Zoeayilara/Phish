def handler(event, context):
    print("Test function invoked!")
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/html',
        },
        'body': '<h1>Netlify Function is working!</h1><p>This is a test function.</p>'
    }
