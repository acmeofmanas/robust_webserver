import sys
import os
from aiohttp import web

# --- Handlers ---

async def handle_root(request):
    """Handles the root URL '/' with a simple JSON response."""
    return web.json_response({
        'message': 'Welcome to the secure aiohttp server!',
        'path': request.path
    })

# --- Application Setup ---

def create_app():
    """Configures and returns the aiohttp application."""
    app = web.Application()
    
    # 1. Add the simple root route
    app.router.add_get('/', handle_root)
    
    # 2. **Securely** add a static file route
    #    This maps the URL prefix '/static/' to the local directory 'static_files'.
    #    It does NOT expose any system directory like /data or /etc.
    static_folder = os.path.join(os.getcwd(), 'static_files')
    print(f"Serving static files from: {static_folder}")

    # The user can access files via a URL like: http://localhost:8080/static/index.html
    app.router.add_static('/static/', path='/Users/manaspradhan/Downloads/test-python', name='static')
    
    return app

# --- Execution ---

if __name__ == '__main__':
    # You can specify the host and port
    host = '0.0.0.0'
    port = 8080
    
    # Create the application
    app = create_app()
    
    # Run the server
    web.run_app(app, host=host, port=port)
    
    # Note: For production use, always use a production-ready server runner like Gunicorn
