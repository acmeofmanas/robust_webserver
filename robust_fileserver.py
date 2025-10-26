#!/usr/bin/env python3
"""
Robust HTTP File Server with support for:
- Large file downloads
- Resume capability (Range requests)
- High latency network handling
- Directory listing
- Configurable chunk size
"""

import os
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
import argparse
import signal
import sys
import socket

class RobustFileHandler(BaseHTTPRequestHandler):
    # Chunk size for streaming (1MB chunks)
    CHUNK_SIZE = 1024 * 1024
    
    # Base directory to serve files from
    BASE_DIR = "/data/"
    
    def do_GET(self):
        """Handle GET requests with range support"""
        try:
            # Decode and sanitize path
            path = unquote(self.path)
            
            # Remove query parameters
            if '?' in path:
                path = path.split('?')[0]
            
            # Security: prevent directory traversal
            full_path = os.path.normpath(os.path.join(self.BASE_DIR, path.lstrip('/')))
            if not full_path.startswith(os.path.abspath(self.BASE_DIR)):
                self.send_error(403, "Forbidden: Access denied")
                return
            
            # Check if path exists
            if not os.path.exists(full_path):
                self.send_error(404, "File not found")
                return
            
            # If directory, show listing
            if os.path.isdir(full_path):
                self.send_directory_listing(full_path, path)
                return
            
            # Serve file with range support
            self.serve_file(full_path)
            
        except Exception as e:
            self.log_error(f"Error handling request: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def serve_file(self, filepath):
        """Serve file with support for partial content (resume)"""
        try:
            file_size = os.path.getsize(filepath)
            
            # Parse Range header
            range_header = self.headers.get('Range')
            
            if range_header:
                # Handle range request (resume support)
                self.handle_range_request(filepath, file_size, range_header)
            else:
                # Handle normal request
                self.handle_full_request(filepath, file_size)
                
        except Exception as e:
            self.log_error(f"Error serving file: {e}")
            self.send_error(500, f"Error serving file: {str(e)}")
    
    def handle_full_request(self, filepath, file_size):
        """Handle complete file download"""
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type is None:
            mime_type = 'application/octet-stream'
        
        self.send_response(200)
        self.send_header('Content-Type', mime_type)
        self.send_header('Content-Length', str(file_size))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(filepath)}"')
        self.end_headers()
        
        # Stream file in chunks
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    self.log_error("Client disconnected during transfer")
                    break
    
    def handle_range_request(self, filepath, file_size, range_header):
        """Handle partial content request (resume support)"""
        try:
            # Parse range header: "bytes=start-end"
            range_spec = range_header.split('=')[1]
            range_start, range_end = range_spec.split('-')
            
            start = int(range_start) if range_start else 0
            end = int(range_end) if range_end else file_size - 1
            
            # Validate range
            if start >= file_size or start < 0 or end >= file_size:
                self.send_error(416, "Requested Range Not Satisfiable")
                return
            
            length = end - start + 1
            
            mime_type, _ = mimetypes.guess_type(filepath)
            if mime_type is None:
                mime_type = 'application/octet-stream'
            
            self.send_response(206)  # Partial Content
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(length))
            self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(filepath)}"')
            self.end_headers()
            
            # Stream requested range
            with open(filepath, 'rb') as f:
                f.seek(start)
                remaining = length
                
                while remaining > 0:
                    chunk_size = min(self.CHUNK_SIZE, remaining)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        self.log_error("Client disconnected during transfer")
                        break
                        
        except Exception as e:
            self.log_error(f"Error handling range request: {e}")
            self.send_error(500, f"Error handling range request: {str(e)}")
    
    def send_directory_listing(self, dirpath, urlpath):
        """Send HTML directory listing"""
        try:
            items = os.listdir(dirpath)
            items.sort()
            
            html = ['<!DOCTYPE html>',
                    '<html><head>',
                    '<meta charset="utf-8">',
                    '<title>Directory listing for {}</title>'.format(urlpath),
                    '<style>',
                    'body { font-family: monospace; margin: 20px; }',
                    'a { text-decoration: none; display: block; padding: 5px; }',
                    'a:hover { background-color: #f0f0f0; }',
                    '.dir { color: #0066cc; font-weight: bold; }',
                    '.file { color: #333; }',
                    '.size { color: #666; margin-left: 20px; }',
                    '</style>',
                    '</head><body>',
                    '<h1>Directory listing for {}</h1>'.format(urlpath),
                    '<hr>']
            
            # Add parent directory link if not root
            if urlpath != '/':
                parent = os.path.dirname(urlpath.rstrip('/'))
                if not parent:
                    parent = '/'
                html.append('<a href="{}" class="dir">📁 ..</a>'.format(parent))
            
            # List directories first, then files
            dirs = []
            files = []
            
            for item in items:
                full_item_path = os.path.join(dirpath, item)
                if os.path.isdir(full_item_path):
                    dirs.append(item)
                else:
                    files.append(item)
            
            # Add directories
            for item in dirs:
                link = os.path.join(urlpath, item).replace('\\', '/')
                html.append('<a href="{}" class="dir">📁 {}/</a>'.format(link, item))
            
            # Add files with sizes
            for item in files:
                link = os.path.join(urlpath, item).replace('\\', '/')
                full_item_path = os.path.join(dirpath, item)
                size = os.path.getsize(full_item_path)
                size_str = self.format_size(size)
                html.append('<a href="{}" class="file">📄 {}<span class="size">{}</span></a>'.format(
                    link, item, size_str))
            
            html.append('<hr></body></html>')
            content = '\n'.join(html).encode('utf-8')
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            self.log_error(f"Error listing directory: {e}")
            self.send_error(500, f"Error listing directory: {str(e)}")
    
    @staticmethod
    def format_size(size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def log_message(self, format, *args):
        """Override to add timestamps to logs"""
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % args))


class RobustHTTPServer(HTTPServer):
    """HTTPServer with improved socket options for high latency networks"""
    
    def server_bind(self):
        """Override to set socket options"""
        # Reuse address to avoid "Address already in use" errors
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Set larger send buffer for better performance over high latency
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)  # 2MB
        
        # Enable TCP keepalive to detect broken connections
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        super().server_bind()


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nShutting down server...")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='Robust HTTP File Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    parser.add_argument('--dir', default='/data/', help='Directory to serve (default: /data/)')
    parser.add_argument('--chunk-size', type=int, default=1024, 
                        help='Chunk size in KB for streaming (default: 1024)')
    
    args = parser.parse_args()
    
    # Set base directory
    RobustFileHandler.BASE_DIR = os.path.abspath(args.dir)
    
    # Set chunk size
    RobustFileHandler.CHUNK_SIZE = args.chunk_size * 1024
    
    # Verify directory exists
    if not os.path.isdir(RobustFileHandler.BASE_DIR):
        print(f"Error: Directory '{RobustFileHandler.BASE_DIR}' does not exist")
        sys.exit(1)
    
    # Setup signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start server
    server_address = (args.host, args.port)
    httpd = RobustHTTPServer(server_address, RobustFileHandler)
    
    print(f"Starting robust file server...")
    print(f"Serving directory: {RobustFileHandler.BASE_DIR}")
    print(f"Server running at http://{args.host}:{args.port}/")
    print(f"Chunk size: {args.chunk_size} KB")
    print(f"Press Ctrl+C to stop\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print("Server stopped.")


if __name__ == '__main__':
    main()
