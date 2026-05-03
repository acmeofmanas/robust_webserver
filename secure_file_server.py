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
import configparser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
from pathlib import Path
import argparse
import signal
import sys
import socket

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.ini')


def load_config(path=CONFIG_FILE):
    cfg = configparser.ConfigParser()
    cfg.read(path)
    return cfg


class AuditLogger:
    def __init__(self, log_dir='./logs', log_to_console=True):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_to_console = log_to_console

        self.audit_file = self.log_dir / f'audit_{datetime.now().strftime("%Y%m%d")}.log'
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)

        fh = logging.FileHandler(self.audit_file)
        fh.setLevel(logging.INFO)
        self.logger.addHandler(fh)

        if self.log_to_console:
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
            self.logger.addHandler(ch)

    def log_request(self, event_type, client_ip, method, path, status_code,
                    bytes_sent=0, range_request=False, error=None, user_agent=None):
        entry = {
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
            entry['error'] = str(error)
        self.logger.info(json.dumps(entry))

    def log_security_event(self, event_type, client_ip, details):
        entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'SECURITY_' + event_type,
            'client_ip': client_ip,
            'details': details,
        }
        self.logger.warning(json.dumps(entry))


class SecureFileHandler(BaseHTTPRequestHandler):
    CHUNK_SIZE = 1024 * 1024
    BASE_DIR = "/data/"
    audit_logger = None

    def do_GET(self):
        start_time = datetime.now()
        bytes_sent = 0
        status_code = 200
        error = None

        try:
            path = unquote(self.path)
            if '?' in path:
                path = path.split('?')[0]

            full_path = os.path.normpath(os.path.join(self.BASE_DIR, path.lstrip('/')))
            if not full_path.startswith(os.path.abspath(self.BASE_DIR)):
                status_code = 403
                self.send_error(403, "Forbidden: Access denied")
                self.audit_logger.log_security_event(
                    'PATH_TRAVERSAL_ATTEMPT',
                    self.client_address[0],
                    f'Attempted path: {path}',
                )
                return

            if not os.path.exists(full_path):
                status_code = 404
                self.send_error(404, "File not found")
                return

            if os.path.isdir(full_path):
                bytes_sent = self.send_directory_listing(full_path, path)
                return

            bytes_sent = self.serve_file(full_path)

        except Exception as e:
            error = e
            status_code = 500
            self.log_error(f"Error handling request: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
        finally:
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
                    user_agent=self.headers.get('User-Agent'),
                )

    def serve_file(self, filepath):
        try:
            file_size = os.path.getsize(filepath)
            range_header = self.headers.get('Range')
            if range_header:
                return self.handle_range_request(filepath, file_size, range_header)
            return self.handle_full_request(filepath, file_size)
        except Exception as e:
            self.log_error(f"Error serving file: {e}")
            self.send_error(500, f"Error serving file: {str(e)}")
            return 0

    def handle_full_request(self, filepath, file_size):
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type is None:
            mime_type = 'application/octet-stream'

        self.send_response(200)
        self.send_header('Content-Type', mime_type)
        self.send_header('Content-Length', str(file_size))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(filepath)}"')
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.end_headers()

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
        try:
            range_spec = range_header.split('=')[1]
            range_start, range_end = range_spec.split('-')

            start = int(range_start) if range_start else 0
            end = int(range_end) if range_end else file_size - 1

            if start >= file_size or start < 0 or end >= file_size:
                self.send_error(416, "Requested Range Not Satisfiable")
                return 0

            length = end - start + 1
            mime_type, _ = mimetypes.guess_type(filepath)
            if mime_type is None:
                mime_type = 'application/octet-stream'

            self.send_response(206)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(length))
            self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(filepath)}"')
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
            self.end_headers()

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
        try:
            items = sorted(os.listdir(dirpath))
            html = [
                '<!DOCTYPE html>', '<html><head>',
                '<meta charset="utf-8">',
                f'<title>Directory listing for {urlpath}</title>',
                '<style>',
                'body { font-family: monospace; margin: 20px; }',
                'a { text-decoration: none; display: block; padding: 5px; }',
                'a:hover { background-color: #f0f0f0; }',
                '.dir { color: #0066cc; font-weight: bold; }',
                '.file { color: #333; }',
                '.size { color: #666; margin-left: 20px; }',
                '</style>',
                '</head><body>',
                f'<h1>Directory listing for {urlpath}</h1>',
                '<hr>',
            ]

            if urlpath != '/':
                parent = os.path.dirname(urlpath.rstrip('/')) or '/'
                html.append(f'<a href="{parent}" class="dir">📁 ..</a>')

            dirs, files = [], []
            for item in items:
                (dirs if os.path.isdir(os.path.join(dirpath, item)) else files).append(item)

            for item in dirs:
                link = os.path.join(urlpath, item).replace('\\', '/')
                html.append(f'<a href="{link}" class="dir">📁 {item}/</a>')

            for item in files:
                link = os.path.join(urlpath, item).replace('\\', '/')
                size_str = self.format_size(os.path.getsize(os.path.join(dirpath, item)))
                html.append(f'<a href="{link}" class="file">📄 {item}<span class="size">{size_str}</span></a>')

            html.append('<hr></body></html>')
            content = '\n'.join(html).encode('utf-8')

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
            self.end_headers()
            self.wfile.write(content)
            return len(content)

        except Exception as e:
            self.log_error(f"Error listing directory: {e}")
            self.send_error(500, f"Error listing directory: {str(e)}")
            return 0

    @staticmethod
    def format_size(size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args,
        ))


class SecureHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass,
                 certfile=None, keyfile=None, ssl_enabled=False):
        super().__init__(server_address, RequestHandlerClass)

        if ssl_enabled:
            if not certfile or not keyfile:
                raise ValueError("SSL enabled but certificate/key files not provided")

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            self.socket = context.wrap_socket(self.socket, server_side=True)

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        super().server_bind()


def generate_self_signed_cert(cert_file, key_file):
    try:
        from OpenSSL import crypto

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Organizational Unit"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        print(f"Generated self-signed certificate: {cert_file}")
        print(f"Generated private key: {key_file}")
        return True

    except ImportError:
        print("Warning: pyOpenSSL not installed. Cannot generate self-signed certificate.")
        print("Install with: pip install pyOpenSSL")
        return False


def signal_handler(sig, frame):
    print("\n\nShutting down server...")
    sys.exit(0)


def main():
    cfg = load_config()
    s = cfg['server'] if 'server' in cfg else {}
    sl = cfg['ssl'] if 'ssl' in cfg else {}
    lg = cfg['logging'] if 'logging' in cfg else {}

    parser = argparse.ArgumentParser(description='Secure HTTPS File Server with Audit Logging')
    parser.add_argument('--config', default=CONFIG_FILE, help='Path to config file')
    parser.add_argument('--host', default=s.get('host', '0.0.0.0'))
    parser.add_argument('--port', type=int, default=s.getint('port', 8443))
    parser.add_argument('--dir', default=s.get('dir', '/data/'))
    parser.add_argument('--chunk-size', type=int, default=s.getint('chunk_size', 1024),
                        help='Chunk size in KB for streaming (default: 1024)')
    parser.add_argument('--ssl', action='store_true', default=sl.getboolean('enabled', False))
    parser.add_argument('--cert', default=sl.get('cert', './server.crt'))
    parser.add_argument('--key', default=sl.get('key', './server.key'))
    parser.add_argument('--generate-cert', action='store_true',
                        default=sl.getboolean('generate_cert', False))
    parser.add_argument('--log-dir', default=lg.get('log_dir', './logs'))
    parser.add_argument('--quiet', action='store_true', default=lg.getboolean('quiet', False))

    args = parser.parse_args()

    if args.generate_cert:
        if generate_self_signed_cert(args.cert, args.key):
            args.ssl = True
        else:
            sys.exit(1)

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

    SecureFileHandler.BASE_DIR = os.path.abspath(args.dir)
    SecureFileHandler.CHUNK_SIZE = args.chunk_size * 1024

    audit_logger = AuditLogger(log_dir=args.log_dir, log_to_console=not args.quiet)
    SecureFileHandler.audit_logger = audit_logger

    if not os.path.isdir(SecureFileHandler.BASE_DIR):
        print(f"Error: Directory '{SecureFileHandler.BASE_DIR}' does not exist")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    httpd = SecureHTTPServer(
        (args.host, args.port),
        SecureFileHandler,
        certfile=args.cert if args.ssl else None,
        keyfile=args.key if args.ssl else None,
        ssl_enabled=args.ssl,
    )

    protocol = 'https' if args.ssl else 'http'
    print(f"Starting secure file server...")
    print(f"Config file   : {args.config}")
    print(f"Protocol      : {protocol.upper()}")
    print(f"Serving dir   : {SecureFileHandler.BASE_DIR}")
    print(f"Listening on  : {protocol}://{args.host}:{args.port}/")
    print(f"Chunk size    : {args.chunk_size} KB")
    print(f"Audit logs    : {args.log_dir}")
    if args.ssl:
        print(f"SSL cert      : {args.cert}")
        print(f"SSL key       : {args.key}")
    print(f"Press Ctrl+C to stop\n")

    audit_logger.log_request('SERVER_START', 'localhost', 'SYSTEM', '/', 200, user_agent='System')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        audit_logger.log_request('SERVER_STOP', 'localhost', 'SYSTEM', '/', 200, user_agent='System')
        httpd.server_close()
        print("Server stopped.")


if __name__ == '__main__':
    main()
