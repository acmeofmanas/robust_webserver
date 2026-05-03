# Robust Webserver

A Python HTTP/HTTPS file server with resumable downloads, directory browsing, and optimized performance for large files and high-latency networks.

## Configuration

All parameters live in **`config.ini`** — edit this file before starting the server. CLI flags always override the config file when provided.

```ini
[server]
host       = 0.0.0.0
port       = 8000
dir        = /data/
chunk_size = 1024       # in KB

[ssl]
enabled       = false
cert          = ./server.crt
key           = ./server.key
generate_cert = false   # auto-generate a self-signed cert on startup

[logging]
log_dir = ./logs
quiet   = false
```

> Any new tunable should be added to `config.ini` under the appropriate section — not hardcoded in the scripts.

---

## Usage

### Basic HTTP server

```bash
# Uses values from config.ini
python robust_fileserver.py

# Override individual values via CLI (config.ini is still the base)
python robust_fileserver.py --host 0.0.0.0 --port 9000 --dir /path/to/files --chunk-size 2048

# Point at a different config file
python robust_fileserver.py --config /etc/myserver/config.ini
```

### Secure HTTPS server

```bash
# Uses values from config.ini  (ssl section controls TLS)
python secure_file_server.py

# Enable SSL via CLI
python secure_file_server.py --ssl --cert ./server.crt --key ./server.key

# Auto-generate a self-signed cert and start HTTPS
python secure_file_server.py --generate-cert
```

### CLI options reference

| Flag | Config key | Default | Description |
|---|---|---|---|
| `--config` | — | `config.ini` | Path to config file |
| `--host` | `server.host` | `0.0.0.0` | Bind address |
| `--port` | `server.port` | `8000` / `8443` | Port number |
| `--dir` | `server.dir` | `/data/` | Directory to serve |
| `--chunk-size` | `server.chunk_size` | `1024` | Streaming chunk size (KB) |
| `--ssl` | `ssl.enabled` | `false` | Enable TLS |
| `--cert` | `ssl.cert` | `./server.crt` | SSL certificate path |
| `--key` | `ssl.key` | `./server.key` | SSL private key path |
| `--generate-cert` | `ssl.generate_cert` | `false` | Auto-generate self-signed cert |
| `--log-dir` | `logging.log_dir` | `./logs` | Audit log directory |
| `--quiet` | `logging.quiet` | `false` | Disable console logging |

---

## Features

- **Resumable downloads** — HTTP Range request support
- **Chunked streaming** — memory-efficient transfer of large files
- **Directory browsing** — HTML listings with human-readable sizes
- **Path traversal protection** — blocks `../` attacks
- **Socket tuning** — 2 MB send buffer, TCP keepalive for high-latency links
- **TLS** (`secure_file_server.py`) — TLS 1.2+, HSTS, configurable ciphers
- **Audit logging** (`secure_file_server.py`) — JSON log per day in `./logs/`

---

## Testing resume capability

```bash
# wget — resumes automatically on reconnect
wget -c http://server:8000/largefile.zip

# curl — resume from where it left off
curl -C - -O http://server:8000/largefile.zip
```
