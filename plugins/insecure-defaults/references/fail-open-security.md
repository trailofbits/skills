# Fail-Open Security Switches

**Report when:** The value taken when configuration is absent disables a security control. The insecure state is the unconfigured state.

**Skip when:** Switches whose unconfigured value is the secure one. Flags read but never consulted at the enforcement point.

Read the default, not the flag name. `REQUIRE_AUTH` defaulting to `'false'` requires nothing.

## VULNERABLE - Report These

**Authentication disabled by default**
```python
# File: config/security.py
REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'false').lower() == 'true'

@app.before_request
def check_auth():
    if not REQUIRE_AUTH:
        return  # Skip auth check
    # ... auth logic
```
**Why vulnerable:** Default is no authentication. App runs insecurely if env var missing.

**CORS allows all origins**
```javascript
// File: server.js
const allowedOrigins = process.env.ALLOWED_ORIGINS || '*';

app.use(cors({ origin: allowedOrigins }));
```
**Why vulnerable:** Default allows requests from any origin. XSS/CSRF risk.

**Debug mode enabled by default**
```python
# File: config.py
DEBUG = os.getenv('DEBUG', 'true').lower() != 'false'  # Default: true

if DEBUG:
    app.config['DEBUG'] = True
    app.config['PROPAGATE_EXCEPTIONS'] = True
```
**Why vulnerable:** Debug mode default. Stack traces leak sensitive info in production.

## SECURE - Skip These

**Authentication required by default**
```python
# File: config/security.py
REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'true').lower() == 'true'  # Default: true

# Or better - crash if not explicitly configured
REQUIRE_AUTH = os.environ['REQUIRE_AUTH'].lower() == 'true'
```

**CORS requires explicit configuration**
```javascript
// File: server.js
if (!process.env.ALLOWED_ORIGINS) {
  throw new Error('ALLOWED_ORIGINS must be configured');
}
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',');

app.use(cors({ origin: allowedOrigins }));
```

**Debug mode disabled by default**
```python
# File: config.py
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'  # Default: false
```
