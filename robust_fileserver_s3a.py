#!/usr/bin/env python3
"""
Robust HTTP File Server with support for:
- Local filesystem  OR  S3 bucket as the base directory
- Large file downloads with chunked streaming
- Resume capability (HTTP Range requests)
- High-latency network handling
- Multi-select directory listing with Download (ZIP) & Delete
- Configurable chunk size
- Multi-threaded request handling

Usage:
  python robust_fileserver.py --dir /data/
  python robust_fileserver.py --dir s3://my-bucket
  python robust_fileserver.py --dir s3://my-bucket/some/prefix/
"""

import os
import json
import mimetypes
import argparse
import signal
import sys
import socket
import zipfile
import io
from abc import ABC, abstractmethod
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import unquote, parse_qs, urlparse


# ---------------------------------------------------------------------------
# Storage backend abstraction
# ---------------------------------------------------------------------------

class StorageBackend(ABC):
    @abstractmethod
    def exists(self, path: str) -> bool: ...
    @abstractmethod
    def is_dir(self, path: str) -> bool: ...
    @abstractmethod
    def get_size(self, path: str) -> int: ...
    @abstractmethod
    def list_dir(self, path: str): ...
    @abstractmethod
    def open_range(self, path: str, start: int, end: int): ...
    @abstractmethod
    def open_full(self, path: str, chunk_size: int): ...
    @abstractmethod
    def delete(self, path: str): ...


# ---------------------------------------------------------------------------
# Local filesystem backend
# ---------------------------------------------------------------------------

class LocalBackend(StorageBackend):
    def __init__(self, base_dir: str, chunk_size: int):
        self.base_dir = os.path.abspath(base_dir)
        self.chunk_size = chunk_size

    def _full_path(self, path: str) -> str:
        joined = os.path.normpath(os.path.join(self.base_dir, path.lstrip("/")))
        if not joined.startswith(self.base_dir):
            raise PermissionError("Directory traversal attempt blocked")
        return joined

    def exists(self, path):
        return os.path.exists(self._full_path(path))

    def is_dir(self, path):
        return os.path.isdir(self._full_path(path))

    def get_size(self, path):
        return os.path.getsize(self._full_path(path))

    def list_dir(self, path):
        full = self._full_path(path)
        for name in sorted(os.listdir(full)):
            item = os.path.join(full, name)
            if os.path.isdir(item):
                yield name, True, None
            else:
                yield name, False, os.path.getsize(item)

    def open_range(self, path, start, end):
        full = self._full_path(path)
        length = end - start + 1
        with open(full, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(self.chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    def open_full(self, path, chunk_size):
        full = self._full_path(path)
        with open(full, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def delete(self, path):
        full = self._full_path(path)
        if os.path.isdir(full):
            import shutil
            shutil.rmtree(full)
        else:
            os.remove(full)


# ---------------------------------------------------------------------------
# S3 backend
# ---------------------------------------------------------------------------

class S3Backend(StorageBackend):
    def __init__(self, bucket: str, prefix: str, chunk_size: int,
                 endpoint_url: str = None, region: str = None):
        try:
            import boto3
            from botocore.exceptions import ClientError
            self._ClientError = ClientError
        except ImportError:
            sys.exit("boto3 is required for S3 support.  pip install boto3")
        import boto3
        session = boto3.session.Session()
        self.s3 = session.client("s3", endpoint_url=endpoint_url, region_name=region)
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        if self.prefix:
            self.prefix += "/"
        self.chunk_size = chunk_size

    def _key(self, url_path: str) -> str:
        parts = [p for p in url_path.split("/") if p not in ("", ".", "..")]
        return self.prefix + "/".join(parts)

    def _prefix_for_path(self, url_path: str) -> str:
        key = self._key(url_path)
        if key and not key.endswith("/"):
            key += "/"
        return key

    def _head(self, key: str):
        try:
            return self.s3.head_object(Bucket=self.bucket, Key=key)
        except self._ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return None
            raise

    def exists(self, url_path):
        if self._head(self._key(url_path)):
            return True
        resp = self.s3.list_objects_v2(Bucket=self.bucket,
                                        Prefix=self._prefix_for_path(url_path), MaxKeys=1)
        return resp.get("KeyCount", 0) > 0

    def is_dir(self, url_path):
        if self._head(self._key(url_path)):
            return False
        resp = self.s3.list_objects_v2(Bucket=self.bucket,
                                        Prefix=self._prefix_for_path(url_path), MaxKeys=1)
        return resp.get("KeyCount", 0) > 0

    def get_size(self, url_path):
        meta = self._head(self._key(url_path))
        if meta is None:
            raise FileNotFoundError(f"S3 key not found: {url_path}")
        return meta["ContentLength"]

    def list_dir(self, url_path):
        prefix = self._prefix_for_path(url_path)
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, Delimiter="/"):
            for cp in page.get("CommonPrefixes") or []:
                name = cp["Prefix"][len(prefix):].rstrip("/")
                if name:
                    yield name, True, None
            for obj in page.get("Contents") or []:
                name = obj["Key"][len(prefix):]
                if name and name != "/":
                    yield name, False, obj["Size"]

    def open_range(self, url_path, start, end):
        resp = self.s3.get_object(Bucket=self.bucket, Key=self._key(url_path),
                                   Range=f"bytes={start}-{end}")
        body = resp["Body"]
        while True:
            chunk = body.read(self.chunk_size)
            if not chunk:
                break
            yield chunk

    def open_full(self, url_path, chunk_size):
        resp = self.s3.get_object(Bucket=self.bucket, Key=self._key(url_path))
        body = resp["Body"]
        while True:
            chunk = body.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def delete(self, url_path):
        if self.is_dir(url_path):
            prefix = self._prefix_for_path(url_path)
            paginator = self.s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
                if objects:
                    self.s3.delete_objects(Bucket=self.bucket, Delete={"Objects": objects})
        else:
            self.s3.delete_object(Bucket=self.bucket, Key=self._key(url_path))


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _fmt_size(size):
    if size is None:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def build_breadcrumb(url_path: str) -> str:
    parts = [p for p in url_path.strip("/").split("/") if p]
    crumbs = ['<a href="/">~</a>']
    for i, part in enumerate(parts):
        href = "/" + "/".join(parts[:i+1])
        crumbs.append(f'<span> / </span><a href="{href}">{part}</a>')
    return "".join(crumbs)


def build_row(name: str, is_dir: bool, size, url_path: str) -> str:
    slash = "/" if is_dir else ""
    link = url_path.rstrip("/") + "/" + name + slash
    icon = "📁" if is_dir else "📄"
    dir_cls = " is-dir" if is_dir else ""
    size_str = "" if is_dir else _fmt_size(size)
    dl_btn = (
        f'<button class="row-action row-dl" '
        f'onclick="downloadSingle(\'{link}\');event.stopPropagation()">↓ dl</button>'
        if not is_dir else ""
    )
    return f"""    <tr data-path="{link}">
      <td><input type="checkbox" class="row-cb" value="{link}"></td>
      <td><div class="name-cell">
        <span class="icon">{icon}</span>
        <a href="{link}" class="name-link{dir_cls}">{name}{slash}</a>
      </div></td>
      <td class="size-cell">{size_str}</td>
      <td><div class="row-actions">
        {dl_btn}
        <button class="row-action row-del" onclick="deleteSingle('{link}');event.stopPropagation()">✕ del</button>
      </div></td>
    </tr>"""


LISTING_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>/{title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  :root{{
    --bg:#0d0f12;--surface:#13161b;--border:#1e2330;--border-h:#2e3550;
    --accent:#4f8ef7;--accent-d:rgba(79,142,247,.12);
    --danger:#f75f5f;--danger-d:rgba(247,95,95,.12);
    --ok:#4fcf8e;--text:#c8d0e0;--dim:#5a6480;--bright:#eef1f8;
    --dir:#7eb8f7;--mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif;
  }}
  body{{background:var(--bg);color:var(--text);font-family:var(--sans);font-weight:300;min-height:100vh}}

  header{{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 28px;
    display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100}}
  .logo{{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.18em;
    color:var(--accent);text-transform:uppercase;opacity:.8;white-space:nowrap}}
  .breadcrumb{{font-family:var(--mono);font-size:13px;color:var(--dim);overflow:hidden;
    text-overflow:ellipsis;white-space:nowrap}}
  .breadcrumb a{{color:var(--text);text-decoration:none}}
  .breadcrumb a:hover{{color:var(--accent)}}
  .breadcrumb span{{color:var(--dim)}}

  .toolbar{{padding:10px 28px;display:flex;align-items:center;gap:10px;
    border-bottom:1px solid var(--border);background:var(--bg);flex-wrap:wrap}}
  .sel-info{{font-family:var(--mono);font-size:12px;color:var(--dim);margin-right:auto;min-width:100px}}
  .sel-info b{{color:var(--accent)}}

  button{{font-family:var(--mono);font-size:12px;font-weight:600;letter-spacing:.06em;
    padding:7px 16px;border-radius:4px;border:1px solid;cursor:pointer;
    transition:background .15s,color .15s,opacity .15s;white-space:nowrap;
    display:inline-flex;align-items:center;gap:6px;background:transparent}}
  .btn-ghost{{border-color:var(--border-h);color:var(--dim)}}
  .btn-ghost:hover{{background:var(--border);color:var(--text)}}
  .btn-primary{{background:var(--accent-d);border-color:var(--accent);color:var(--accent)}}
  .btn-primary:hover{{background:rgba(79,142,247,.22)}}
  .btn-primary:disabled,.btn-danger:disabled{{opacity:.3;cursor:not-allowed;pointer-events:none}}
  .btn-danger{{background:var(--danger-d);border-color:var(--danger);color:var(--danger)}}
  .btn-danger:hover{{background:rgba(247,95,95,.22)}}

  table{{width:100%;border-collapse:collapse}}
  thead th{{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;
    color:var(--dim);font-weight:600;padding:10px 14px;text-align:left;
    border-bottom:1px solid var(--border);background:var(--bg);user-select:none;white-space:nowrap}}
  thead th:first-child{{padding-left:28px;width:36px}}
  thead th:last-child{{padding-right:28px;text-align:right}}

  tbody tr{{border-bottom:1px solid var(--border);transition:background .1s;cursor:pointer}}
  tbody tr:hover{{background:rgba(255,255,255,.025)}}
  tbody tr.selected{{background:var(--accent-d)!important}}

  td{{padding:11px 14px;font-size:14px;vertical-align:middle}}
  td:first-child{{padding-left:28px}}
  td:last-child{{padding-right:28px;text-align:right}}

  input[type=checkbox]{{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}}

  .name-cell{{display:flex;align-items:center;gap:10px}}
  .icon{{font-size:16px;line-height:1;flex-shrink:0}}
  .name-link{{font-family:var(--mono);font-size:13px;color:var(--bright);text-decoration:none;word-break:break-all}}
  .name-link:hover{{color:var(--accent)}}
  .name-link.is-dir{{color:var(--dir)}}
  .name-link.is-dir:hover{{color:#a8d0ff}}
  .size-cell{{font-family:var(--mono);font-size:12px;color:var(--dim)}}

  .row-actions{{display:flex;gap:8px;justify-content:flex-end;opacity:0;transition:opacity .15s}}
  tr:hover .row-actions{{opacity:1}}
  .row-action{{font-family:var(--mono);font-size:11px;padding:4px 10px;border-radius:3px;
    border:1px solid;cursor:pointer;text-decoration:none;background:transparent}}
  .row-dl{{border-color:var(--accent);color:var(--accent)}}
  .row-dl:hover{{background:var(--accent-d)}}
  .row-del{{border-color:var(--danger);color:var(--danger)}}
  .row-del:hover{{background:var(--danger-d)}}

  .empty{{text-align:center;padding:80px 20px;color:var(--dim);font-family:var(--mono);font-size:13px}}

  #toast{{position:fixed;bottom:28px;right:28px;padding:12px 20px;border-radius:6px;
    font-family:var(--mono);font-size:13px;font-weight:600;border:1px solid;
    opacity:0;transform:translateY(12px);transition:opacity .25s,transform .25s;
    pointer-events:none;z-index:999}}
  #toast.show{{opacity:1;transform:translateY(0)}}
  #toast.ok{{background:rgba(79,207,142,.1);border-color:var(--ok);color:var(--ok)}}
  #toast.err{{background:var(--danger-d);border-color:var(--danger);color:var(--danger)}}

  #backdrop{{position:fixed;inset:0;background:rgba(0,0,0,.65);display:none;
    align-items:center;justify-content:center;z-index:200}}
  #backdrop.open{{display:flex}}
  #modal{{background:var(--surface);border:1px solid var(--border-h);border-radius:8px;
    padding:32px;max-width:420px;width:90%}}
  #modal h2{{font-family:var(--mono);font-size:15px;font-weight:600;color:var(--danger);margin-bottom:12px}}
  #modal p{{font-size:14px;color:var(--text);margin-bottom:24px;line-height:1.6}}
  #modal p b{{color:var(--bright)}}
  .modal-actions{{display:flex;gap:10px;justify-content:flex-end}}
</style>
</head>
<body>

<header>
  <span class="logo">fileserv</span>
  <span class="breadcrumb">{breadcrumb}</span>
</header>

<div class="toolbar">
  <input type="checkbox" id="sel-all" title="Select all">
  <span class="sel-info" id="sel-info">0 selected</span>
  <button class="btn-ghost" onclick="invertSel()">Invert</button>
  <button class="btn-primary" id="btn-dl"  disabled onclick="downloadSel()">⬇ Download</button>
  <button class="btn-danger"  id="btn-del" disabled onclick="confirmDel()">✕ Delete</button>
</div>

<table>
  <thead><tr>
    <th></th><th>Name</th><th>Size</th><th>Actions</th>
  </tr></thead>
  <tbody id="file-list">
{rows}
  </tbody>
</table>
{empty_state}

<div id="toast"></div>
<div id="backdrop">
  <div id="modal">
    <h2>⚠ Confirm Delete</h2>
    <p id="modal-msg"></p>
    <div class="modal-actions">
      <button class="btn-ghost" onclick="closeModal()">Cancel</button>
      <button class="btn-danger" onclick="execDelete()">Delete</button>
    </div>
  </div>
</div>

<script>
let pending = [];

function checked() {{ return [...document.querySelectorAll('.row-cb:checked')]; }}

function updateBar() {{
  const c = checked(), n = c.length, total = document.querySelectorAll('.row-cb').length;
  document.getElementById('sel-info').innerHTML = n ? '<b>' + n + '</b> selected' : '0 selected';
  document.getElementById('btn-dl').disabled  = !n;
  document.getElementById('btn-del').disabled = !n;
  const sa = document.getElementById('sel-all');
  sa.indeterminate = n > 0 && n < total;
  sa.checked = n > 0 && n === total;
}}

document.getElementById('sel-all').addEventListener('change', function() {{
  document.querySelectorAll('.row-cb').forEach(cb => {{ cb.checked = this.checked; cb.closest('tr').classList.toggle('selected', this.checked); }});
  updateBar();
}});
document.querySelectorAll('.row-cb').forEach(cb => {{
  cb.addEventListener('change', function() {{ this.closest('tr').classList.toggle('selected', this.checked); updateBar(); }});
}});
document.querySelectorAll('tr[data-path]').forEach(tr => {{
  tr.addEventListener('click', function(e) {{
    if (['A','INPUT','BUTTON'].includes(e.target.tagName) || e.target.closest('a') || e.target.closest('button')) return;
    const cb = this.querySelector('.row-cb');
    if (!cb) return;
    cb.checked = !cb.checked;
    this.classList.toggle('selected', cb.checked);
    updateBar();
  }});
}});

function invertSel() {{
  document.querySelectorAll('.row-cb').forEach(cb => {{ cb.checked = !cb.checked; cb.closest('tr').classList.toggle('selected', cb.checked); }});
  updateBar();
}}

function downloadSingle(path) {{ window.location.href = path; }}

function downloadSel() {{
  const paths = checked().map(cb => cb.value);
  if (paths.length === 1 && !paths[0].endsWith('/')) {{ window.location.href = paths[0]; return; }}
  const form = document.createElement('form');
  form.method = 'POST'; form.action = '/__action__/download';
  paths.forEach(p => {{ const i = document.createElement('input'); i.type='hidden'; i.name='paths'; i.value=p; form.appendChild(i); }});
  document.body.appendChild(form); form.submit(); document.body.removeChild(form);
}}

function confirmDel(paths) {{
  pending = paths || checked().map(cb => cb.value);
  const n = pending.length;
  document.getElementById('modal-msg').innerHTML = 'Permanently delete <b>' + n + ' item' + (n>1?'s':'') + '</b>. This cannot be undone.';
  document.getElementById('backdrop').classList.add('open');
}}
function closeModal() {{ document.getElementById('backdrop').classList.remove('open'); pending = []; }}
function deleteSingle(path) {{ confirmDel([path]); }}

async function execDelete() {{
  closeModal();
  const res = await fetch('/__action__/delete', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{paths:pending}})}});
  const data = await res.json();
  if (data.ok) {{ toast('Deleted ' + pending.length + ' item(s)', 'ok'); setTimeout(() => location.reload(), 900); }}
  else toast('Delete failed: ' + (data.error || 'unknown'), 'err');
}}

let _tt;
function toast(msg, type) {{
  const el = document.getElementById('toast');
  el.textContent = msg; el.className = 'show ' + type;
  clearTimeout(_tt); _tt = setTimeout(() => el.className = '', 3200);
}}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class RobustFileHandler(BaseHTTPRequestHandler):
    CHUNK_SIZE: int = 1024 * 1024
    BACKEND: StorageBackend = None

    def do_GET(self):
        parsed = urlparse(self.path)
        try:
            url_path = self._clean(parsed.path)
        except PermissionError:
            self.send_error(403, "Forbidden")
            return

        backend = self.BACKEND
        if not backend.exists(url_path):
            self.send_error(404, "File not found")
            return
        if backend.is_dir(url_path):
            self.send_listing(url_path)
            return
        self.serve_file(url_path)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/__action__/download":
            self._batch_download()
        elif path == "/__action__/delete":
            self._batch_delete()
        else:
            self.send_error(405, "Method Not Allowed")

    # ── file serving ──────────────────────────────────────────────────

    def serve_file(self, url_path):
        try:
            size = self.BACKEND.get_size(url_path)
            rh = self.headers.get("Range")
            if rh:
                self._serve_range(url_path, size, rh)
            else:
                self._serve_full(url_path, size)
        except Exception as e:
            self.log_error("serve_file error: %s", e)
            self.send_error(500, str(e))

    def _serve_full(self, path, size):
        fn = path.split("/")[-1]
        self.send_response(200)
        self.send_header("Content-Type", self._mime(path))
        self.send_header("Content-Length", str(size))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Disposition", f'attachment; filename="{fn}"')
        self.end_headers()
        self._stream(self.BACKEND.open_full(path, self.CHUNK_SIZE))

    def _serve_range(self, path, size, rh):
        try:
            spec = rh.split("=")[1]
            s, e = spec.split("-")
            start = int(s) if s else 0
            end   = int(e) if e else size - 1
        except (IndexError, ValueError):
            self.send_error(400, "Bad Range header"); return
        if start < 0 or start >= size or end >= size or start > end:
            self.send_error(416, "Requested Range Not Satisfiable"); return
        fn = path.split("/")[-1]
        self.send_response(206)
        self.send_header("Content-Type", self._mime(path))
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Disposition", f'attachment; filename="{fn}"')
        self.end_headers()
        self._stream(self.BACKEND.open_range(path, start, end))

    def _stream(self, chunks):
        try:
            for chunk in chunks:
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            self.log_error("client disconnected")

    # ── batch download (zip) ──────────────────────────────────────────

    def _batch_download(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        paths = parse_qs(body).get("paths", [])
        if not paths:
            self.send_error(400, "No paths"); return
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in paths:
                p = self._clean(p)
                if self.BACKEND.is_dir(p):
                    self._zip_dir(zf, p)
                elif self.BACKEND.exists(p):
                    data = b"".join(self.BACKEND.open_full(p, self.CHUNK_SIZE))
                    zf.writestr(p.lstrip("/"), data)
        zb = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(zb)))
        self.send_header("Content-Disposition", 'attachment; filename="download.zip"')
        self.end_headers()
        self.wfile.write(zb)

    def _zip_dir(self, zf, dir_path):
        for name, is_dir, _ in self.BACKEND.list_dir(dir_path):
            child = dir_path.rstrip("/") + "/" + name
            if is_dir:
                self._zip_dir(zf, child)
            else:
                data = b"".join(self.BACKEND.open_full(child, self.CHUNK_SIZE))
                zf.writestr(child.lstrip("/"), data)

    # ── batch delete ──────────────────────────────────────────────────

    def _batch_delete(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        try:
            paths = json.loads(body).get("paths", [])
        except json.JSONDecodeError:
            self._json({"ok": False, "error": "Bad JSON"}, 400); return
        errors = []
        for p in paths:
            try:
                self.BACKEND.delete(self._clean(p))
            except Exception as ex:
                errors.append(str(ex))
        if errors:
            self._json({"ok": False, "error": "; ".join(errors)}, 500)
        else:
            self._json({"ok": True, "deleted": len(paths)})

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── directory listing ─────────────────────────────────────────────

    def send_listing(self, url_path):
        try:
            entries = list(self.BACKEND.list_dir(url_path))
        except Exception as e:
            self.log_error("list_dir error: %s", e)
            self.send_error(500, str(e)); return

        rows = []
        stripped = url_path.strip("/")
        if stripped:
            parent = "/" + "/".join(stripped.split("/")[:-1])
            rows.append(f"""    <tr data-path="{parent or '/'}">
      <td></td>
      <td><div class="name-cell"><span class="icon">📁</span>
        <a href="{parent or '/'}" class="name-link is-dir">..</a>
      </div></td><td class="size-cell"></td><td></td></tr>""")

        for name, is_dir, size in entries:
            rows.append(build_row(name, is_dir, size, url_path))

        empty = '<div class="empty">This directory is empty.</div>' if not entries else ""
        title = url_path.strip("/") or "root"

        html = LISTING_HTML.format(
            title=title,
            breadcrumb=build_breadcrumb(url_path),
            rows="\n".join(rows),
            empty_state=empty,
        )
        content = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    # ── helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _clean(path: str) -> str:
        path = unquote(path).split("?")[0]
        parts = [p for p in path.split("/") if p not in ("", ".", "..")]
        return "/" + "/".join(parts)

    @staticmethod
    def _mime(path: str) -> str:
        m, _ = mimetypes.guess_type(path)
        return m or "application/octet-stream"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (
            self.address_string(), self.log_date_time_string(), fmt % args))


# ---------------------------------------------------------------------------
# Threaded server
# ---------------------------------------------------------------------------

class RobustHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        super().server_bind()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_s3_url(url):
    rest = url[5:]
    bucket, prefix = (rest.split("/", 1) if "/" in rest else (rest, ""))
    return bucket, prefix


def main():
    parser = argparse.ArgumentParser(description="Robust HTTP File Server — local or S3")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--dir", default="/data/", help="Local path or s3://bucket[/prefix]")
    parser.add_argument("--chunk-size", type=int, default=1024, help="Chunk size in KB")
    parser.add_argument("--s3-endpoint", default=None)
    parser.add_argument("--s3-region", default=None)
    args = parser.parse_args()

    chunk_bytes = args.chunk_size * 1024
    RobustFileHandler.CHUNK_SIZE = chunk_bytes

    if args.dir.startswith("s3://"):
        bucket, prefix = parse_s3_url(args.dir)
        backend = S3Backend(bucket=bucket, prefix=prefix, chunk_size=chunk_bytes,
                            endpoint_url=args.s3_endpoint, region=args.s3_region)
        loc = args.dir
    else:
        base = os.path.abspath(args.dir)
        if not os.path.isdir(base):
            sys.exit(f"Error: '{base}' does not exist")
        backend = LocalBackend(base_dir=base, chunk_size=chunk_bytes)
        loc = base

    RobustFileHandler.BACKEND = backend
    signal.signal(signal.SIGINT, lambda s, f: (print("\nShutting down…"), sys.exit(0)))

    httpd = RobustHTTPServer((args.host, args.port), RobustFileHandler)
    print(f"Robust file server\n  Backend : {loc}\n  Address : http://{args.host}:{args.port}/\n  Chunk   : {args.chunk_size} KB\nCtrl+C to stop\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print("Stopped.")


if __name__ == "__main__":
    main()
