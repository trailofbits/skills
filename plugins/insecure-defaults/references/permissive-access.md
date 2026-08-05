# Permissive Access Defaults

**Report when:** Access is granted to a party who should not have it, either because that is the hardcoded value (ACL='public-read', mode 0o666, Access-Control-Allow-Origin '*') or because it is what the unconfigured state falls back to. Both count; most real cases are hardcoded, with no configuration involved at all.

**Skip when:** Deliberate public endpoints with a stated reason. Local-only dev servers. Permissiveness already gated by an outer authorization layer at the same trust boundary.

Ask who gains access, not how wide the value looks. `0o644` on a CDN asset is correct; `0o666` on a key file is not.

## VULNERABLE - Report These

**File permissions world-writable**
```python
# File: src/storage/files.py
def create_secure_file(path):
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o666)  # rw-rw-rw-
    return fd
```
**Why vulnerable:** Any user can write to file. Should be 0o600 or 0o644.

**S3 bucket public by default**
```python
# File: infrastructure/storage.py
def create_storage_bucket(name):
    bucket = s3.create_bucket(
        Bucket=name,
        ACL='public-read'  # Publicly readable by default
    )
```
**Why vulnerable:** Sensitive data exposed publicly. Should require explicit configuration.

**API allows any origin**
```python
# File: app.py
@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```
**Why vulnerable:** CORS misconfiguration. Allows credential theft from any site.

## SECURE - Skip These

**Explicitly configured permissiveness with justification**
```python
# File: src/storage/public_assets.py
def create_public_asset(path):
    """Create world-readable asset for CDN distribution"""
    # Intentionally public - static assets only
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o644)
    return fd
```

**Restrictive by default**
```python
# File: infrastructure/storage.py
def create_storage_bucket(name, public=False):
    acl = 'public-read' if public else 'private'
    if public:
        logger.warning(f'Creating PUBLIC bucket: {name}')
    bucket = s3.create_bucket(Bucket=name, ACL=acl)
```
