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
import configparser
import signal
import sys
import socket

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.ini')


def load_config(path=CONFIG_FILE):
    cfg = configparser.ConfigParser()
    cfg.read(path)
    return cfg


class RobustFileHandler(BaseHTTPRequestHandler):
    CHUNK_SIZE = 1024 * 1024
    BASE_DIR = "/data/"

    def do_GET(self):
        try:
            path = unquote(self.path)
            if '?' in path:
                path = path.split('?')[0]

            full_path = os.path.normpath(os.path.join(self.BASE_DIR, path.lstrip('/')))
            if not full_path.startswith(os.path.abspath(self.BASE_DIR)):
                self.send_error(403, "Forbidden: Access denied")
                return

            if not os.path.exists(full_path):
                self.send_error(404, "File not found")
                return

            if os.path.isdir(full_path):
                self.send_directory_listing(full_path, path)
                return

            self.serve_file(full_path)

        except Exception as e:
            self.log_error(f"Error handling request: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")

    def serve_file(self, filepath):
        try:
            file_size = os.path.getsize(filepath)
            range_header = self.headers.get('Range')
            if range_header:
                self.handle_range_request(filepath, file_size, range_header)
            else:
                self.handle_full_request(filepath, file_size)
        except Exception as e:
            self.log_error(f"Error serving file: {e}")
            self.send_error(500, f"Error serving file: {str(e)}")

    def handle_full_request(self, filepath, file_size):
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type is None:
            mime_type = 'application/octet-stream'

        self.send_response(200)
        self.send_header('Content-Type', mime_type)
        self.send_header('Content-Length', str(file_size))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(filepath)}"')
        self.end_headers()

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
        try:
            range_spec = range_header.split('=')[1]
            range_start, range_end = range_spec.split('-')

            start = int(range_start) if range_start else 0
            end = int(range_end) if range_end else file_size - 1

            if start >= file_size or start < 0 or end >= file_size:
                self.send_error(416, "Requested Range Not Satisfiable")
                return

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
            self.end_headers()

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
            self.end_headers()
            self.wfile.write(content)

        except Exception as e:
            self.log_error(f"Error listing directory: {e}")
            self.send_error(500, f"Error listing directory: {str(e)}")

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


class RobustHTTPServer(HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        super().server_bind()


def signal_handler(sig, frame):
    print("\n\nShutting down server...")
    sys.exit(0)


def main():
    cfg = load_config()
    s = cfg['server'] if 'server' in cfg else {}

    parser = argparse.ArgumentParser(description='Robust HTTP File Server')
    parser.add_argument('--config', default=CONFIG_FILE, help='Path to config file')
    parser.add_argument('--host', default=s.get('host', '0.0.0.0'))
    parser.add_argument('--port', type=int, default=s.getint('port', 8000))
    parser.add_argument('--dir', default=s.get('dir', '/data/'))
    parser.add_argument('--chunk-size', type=int, default=s.getint('chunk_size', 1024),
                        help='Chunk size in KB for streaming (default: 1024)')

    args = parser.parse_args()

    # Reload config if a custom path was given
    if args.config != CONFIG_FILE:
        cfg = load_config(args.config)
        s = cfg['server'] if 'server' in cfg else {}
        # Re-apply config defaults (CLI still wins because argparse already parsed)

    RobustFileHandler.BASE_DIR = os.path.abspath(args.dir)
    RobustFileHandler.CHUNK_SIZE = args.chunk_size * 1024

    if not os.path.isdir(RobustFileHandler.BASE_DIR):
        print(f"Error: Directory '{RobustFileHandler.BASE_DIR}' does not exist")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    httpd = RobustHTTPServer((args.host, args.port), RobustFileHandler)

    print(f"Starting robust file server...")
    print(f"Config file   : {args.config}")
    print(f"Serving dir   : {RobustFileHandler.BASE_DIR}")
    print(f"Listening on  : http://{args.host}:{args.port}/")
    print(f"Chunk size    : {args.chunk_size} KB")
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
