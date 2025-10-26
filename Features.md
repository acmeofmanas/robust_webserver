Key Features:

Resume Support (HTTP Range Requests): Allows downloads to be paused and resumed, critical for unreliable connections
Chunked Streaming: Sends files in configurable chunks (default 1MB) to handle memory efficiently
Connection Handling: Properly handles broken connections and client disconnects
Directory Listing: Browse folders with a clean HTML interface
Security: Prevents directory traversal attacks
Optimized Socket Options:

Larger send buffers (2MB) for high-latency networks
TCP keepalive to detect dead connections
SO_REUSEADDR for quick restarts



