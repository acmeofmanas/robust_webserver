usage 
# Basic usage (serves /data/ on port 8000)
python robust_fileserver.py

# Custom options
python robust_fileserver.py --host 0.0.0.0 --port 9000 --dir /path/to/files --chunk-size 2048

# Options:
#   --host: IP to bind to (default: 0.0.0.0 for all interfaces)
#   --port: Port number (default: 8000)
#   --dir: Directory to serve (default: /data/)
#   --chunk-size: Chunk size in KB (default: 1024)
