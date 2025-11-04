#!/usr/bin/env python3
"""
Robust HTTPS File Server with:
- SSL/TLS encryption
- Large file downloads with resume capability
- Comprehensive audit logging
- High latency network handling
- Directory listing
"""

import os
import ssl
import json
import logging
import mimetypes
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
from pathlib import Path
import argparse
import signal
import sys
import socket
import hashlib

class AuditLogger:
    """Handles comprehensive audit logging"""
    
    def __init__(self, log_dir='./logs', log_to_console=True):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_to_console = log_to_console
        
        # Setup file handler for audit log
        self.audit_file = self.log_dir / f'audit_{datetime.now().strftime("%Y%m%d")}.log'
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        
        # File handler (JSON format)
        fh = logging.FileHandler(self.audit_file)
        fh.setLevel(logging.INFO)
        self.logger.addHandler(fh)
        
        # Console handler (human readable)
        if self.log_to_console:
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
    
    def log_request(self, event_type, client_ip, method, path, status_code, 
                   bytes_sent=0, range_request=False, error=None, user_agent=None):
        """Log request with comprehensive details"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'client_ip': client_ip,
            'method': method,
            'path': path,
            'status_code': status_code,
            'bytes_sent': bytes_sent,
            'range_request': range_request,
            'user_agent': user_agent,
        }
        
        if error:
            log_entry['error'] = str(error)
        
        self.logger.info(json.dumps(log_entry))
    
    def log_security_event(self, event_type, client_ip, details):
        """Log security-related events"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'SECURITY_' + event_type,
            'client_ip': client_ip,
            'details': details
        }
        self.logger.warning(json.dumps(log_entry))


class SecureFileHandler(BaseHTTPRequestHandler):
    # Chunk size for streaming (1MB chunks)
    CHUNK_SIZE = 1024 * 1024
    
    # Base directory to serve files from
    BASE_DIR = "/data/"
    
    # Audit logger instance
    audit_logger = None
    
    def do_GET(self):
        """Handle GET requests with range support"""
        start_time = datetime.now()
        bytes_sent = 0
        status_code = 200
        error = None
        
        try:
            # Decode and sanitize path
            path = unquote(self.path)
            
            # Remove query parameters
            if '?' in path:
                path = path.split('?')[0]
            
            # Security: prevent directory traversal
            full_path = os.path.normpath(os.path.join(self.BASE_DIR, path.lstrip('/')))
            if not full_path.startswith(os.path.abspath(self.BASE_DIR)):
                status_code = 403
                self.send_error(403, "Forbidden: Access denied")
                self.audit_logger.log_security_event(
                    'PATH_TRAVERSAL_ATTEMPT',
                    self.client_address[0],
                    f'Attempted path: {path}'
                )
                return
            
            # Check if path exists
            if not os.path.exists(full_path):
                status_code = 404
                self.send_error(404, "File not found")
                return
            
            # If directory, show listing
            if os.path.isdir(full_path):
                bytes_sent = self.send_directory_listing(full_path, path)
                return
            
            # Serve file with range support
            bytes_sent = self.serve_file(full_path)
            
        except Exception as e:
            error = e
            status_code = 500
            self.log_error(f"Error handling request: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
        finally:
            # Audit log
            if self.audit_logger:
                self.audit_logger.log_request(
                    'FILE_ACCESS',
                    self.client_address[0],
                    'GET',
                    self.path,
                    status_code,
                    bytes_sent=bytes_sent,
                    range_request='Range' in self.headers,
                    error=error,
                    user_agent=self.headers.get('User-Agent')
                )
    
    def serve_file(self, filepath):
        """Serve file with support for partial content (resume)"""
        try:
            file_size = os.path.getsize(filepath)
            
            # Parse Range header
            range_header = self.headers.get('Range')
            
            if range_header:
                # Handle range request (resume support)
                return self.handle_range_request(filepath, file_size, range_header)
            else:
                # Handle normal request
                return self.handle_full_request(filepath, file_size)
                
        except Exception as e:
            self.log_error(f"Error serving file: {e}")
            self.send_error(500, f"Error serving file: {str(e)}")
            return 0
    
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
        self.send_header('Strict-Transport-Security', 'max-age=31536000')  # HSTS
        self.end_headers()
        
        # Stream file in chunks
        bytes_sent = 0
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                    bytes_sent += len(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    self.log_error("Client disconnected during transfer")
                    break
        
        return bytes_sent
    
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
                return 0
            
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
            self.send_header('Strict-Transport-Security', 'max-age=31536000')  # HSTS
            self.end_headers()
            
            # Stream requested range
            bytes_sent = 0
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
                        bytes_sent += len(chunk)
                        remaining -= len(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        self.log_error("Client disconnected during transfer")
                        break
            
            return bytes_sent
                        
        except Exception as e:
            self.log_error(f"Error handling range request: {e}")
            self.send_error(500, f"Error handling range request: {str(e)}")
            return 0
    
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
            self.send_header('Strict-Transport-Security', 'max-age=31536000')  # HSTS
            self.end_headers()
            self.wfile.write(content)
            
            return len(content)
            
        except Exception as e:
            self.log_error(f"Error listing directory: {e}")
            self.send_error(500, f"Error listing directory: {str(e)}")
            return 0
    
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


class SecureHTTPServer(HTTPServer):
    """HTTPServer with SSL and improved socket options"""
    
    def __init__(self, server_address, RequestHandlerClass, 
                 certfile=None, keyfile=None, ssl_enabled=False):
        super().__init__(server_address, RequestHandlerClass)
        
        if ssl_enabled:
            if not certfile or not keyfile:
                raise ValueError("SSL enabled but certificate/key files not provided")
            
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            
            # Security settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            # Wrap socket with SSL
            self.socket = context.wrap_socket(self.socket, server_side=True)
    
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
    parser = argparse.ArgumentParser(description='Secure HTTPS File Server with Audit Logging')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8443, help='Port to bind to (default: 8443)')
    parser.add_argument('--dir', default='/data/', help='Directory to serve (default: /data/)')
    parser.add_argument('--chunk-size', type=int, default=1024, 
                        help='Chunk size in KB for streaming (default: 1024)')
    parser.add_argument('--ssl', action='store_true', help='Enable SSL/TLS')
    parser.add_argument('--cert', help='SSL certificate file path')
    parser.add_argument('--key', help='SSL private key file path')
    parser.add_argument('--log-dir', default='./logs', help='Audit log directory (default: ./logs)')
    parser.add_argument('--quiet', action='store_true', help='Disable console logging')
    
    args = parser.parse_args()
    
    # Validate SSL arguments
    if args.ssl:
        if not args.cert or not args.key:
            print("Error: --cert and --key required when --ssl is enabled")
            sys.exit(1)
        if not os.path.exists(args.cert):
            print(f"Error: Certificate file not found: {args.cert}")
            sys.exit(1)
        if not os.path.exists(args.key):
            print(f"Error: Key file not found: {args.key}")
            sys.exit(1)
    
    # Set base directory
    SecureFileHandler.BASE_DIR = os.path.abspath(args.dir)
    
    # Set chunk size
    SecureFileHandler.CHUNK_SIZE = args.chunk_size * 1024
    
    # Initialize audit logger
    audit_logger = AuditLogger(log_dir=args.log_dir, log_to_console=not args.quiet)
    SecureFileHandler.audit_logger = audit_logger
    
    # Verify directory exists
    if not os.path.isdir(SecureFileHandler.BASE_DIR):
        print(f"Error: Directory '{SecureFileHandler.BASE_DIR}' does not exist")
        sys.exit(1)
    
    # Setup signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start server
    server_address = (args.host, args.port)
    httpd = SecureHTTPServer(
        server_address, 
        SecureFileHandler,
        certfile=args.cert if args.ssl else None,
        keyfile=args.key if args.ssl else None,
        ssl_enabled=args.ssl
    )
    
    protocol = 'https' if args.ssl else 'http'
    print(f"Starting secure file server...")
    print(f"Protocol: {protocol.upper()}")
    print(f"Serving directory: {SecureFileHandler.BASE_DIR}")
    print(f"Server running at {protocol}://{args.host}:{args.port}/")
    print(f"Chunk size: {args.chunk_size} KB")
    print(f"Audit logs: {args.log_dir}")
    if args.ssl:
        print(f"SSL Certificate: {args.cert}")
        print(f"SSL Key: {args.key}")
    print(f"Press Ctrl+C to stop\n")
    
    # Log server start
    audit_logger.log_request(
        'SERVER_START',
        'localhost',
        'SYSTEM',
        '/',
        200,
        user_agent='System'
    )
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        # Log server stop
        audit_logger.log_request(
            'SERVER_STOP',
            'localhost',
            'SYSTEM',
            '/',
            200,
            user_agent='System'
        )
        httpd.server_close()
        print("Server stopped.")


if __name__ == '__main__':
    main()