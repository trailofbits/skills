# Fallback Secrets

**Report when:** A default value supplied when the env var is absent, where that value feeds signing, encryption, session, or token machinery.

**Skip when:** Defaults generated per-boot at random. Values only used as cache keys or correlation ids.

The decisive question is not whether a literal exists. It is whether the app **runs** with it. `env.get(X, Y)` runs; `env[X]` crashes. That difference is the whole finding.

## VULNERABLE - Report These

**Python: Environment variable with fallback**
```python
# File: src/auth/jwt.py
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-123')

# Used in security context
def create_token(user_id):
    return jwt.encode({'user_id': user_id}, SECRET_KEY, algorithm='HS256')
```
**Why vulnerable:** App runs with known secret if `SECRET_KEY` is missing. Attacker can forge tokens.

**JavaScript: Logical OR fallback**
```javascript
// File: config/database.js
const DB_PASSWORD = process.env.DB_PASSWORD || 'admin123';

const pool = new Pool({
  user: 'admin',
  password: DB_PASSWORD,
  database: 'production'
});
```
**Why vulnerable:** Database accepts hardcoded password in production if env var missing.

**Ruby: fetch with default**
```ruby
# File: config/secrets.rb
Rails.application.credentials.secret_key_base =
  ENV.fetch('SECRET_KEY_BASE', 'fallback-secret-base')
```
**Why vulnerable:** Rails session encryption uses weak known key as fallback.

## SECURE - Skip These

**Fail-secure: Crashes without config**
```python
# File: src/auth/jwt.py
SECRET_KEY = os.environ['SECRET_KEY']  # Raises KeyError if missing

# App won't start without SECRET_KEY - fail-secure
```

**Explicit validation**
```javascript
// File: config/database.js
if (!process.env.DB_PASSWORD) {
  throw new Error('DB_PASSWORD environment variable required');
}
const DB_PASSWORD = process.env.DB_PASSWORD;
```

**Test fixtures (clearly scoped)**
```python
# File: tests/fixtures/auth.py
TEST_SECRET = 'test-secret-key-123'  # OK - test-only

# Usage in test
def test_token_creation():
    token = create_token('user1', secret=TEST_SECRET)
```
