# Default Credentials

**Report when:** A credential literal that a running deployment can actually authenticate with, including seeded accounts created on first boot.

**Skip when:** Accounts created disabled or with a forced-reset flag. Credentials in docs, READMEs, and fixture files.

A credential in prose is a credential nobody can use. A credential in `bootstrap_admin()` is a login.

## VULNERABLE - Report These

**Hardcoded admin account**
```python
# File: src/models/user.py
def bootstrap_admin():
    """Create default admin account if none exists"""
    if not User.query.filter_by(role='admin').first():
        admin = User(
            username='admin',
            password=hash_password('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
```
**Why vulnerable:** Default admin account created on first run with known credentials.

**API key in code**
```javascript
// File: src/integrations/payment.js
const STRIPE_API_KEY = process.env.STRIPE_KEY || 'sk_tes...';

const stripe = require('stripe')(STRIPE_API_KEY);
```
**Why vulnerable:** Uses test API key if env var missing. Might reach production.

**Database connection string**
```java
// File: DatabaseConfig.java
private static final String DB_URL = System.getenv().getOrDefault(
    "DATABASE_URL",
    "postgresql://admin:password@localhost:5432/prod"
);
```
**Why vulnerable:** Hardcoded database credentials as fallback.

## SECURE - Skip These

**Disabled default account**
```python
# File: src/models/user.py
def bootstrap_admin():
    """Admin account MUST be configured via environment"""
    username = os.environ['ADMIN_USERNAME']
    password = os.environ['ADMIN_PASSWORD']

    if not User.query.filter_by(username=username).first():
        admin = User(username=username, password=hash_password(password), role='admin')
        db.session.add(admin)
```

**Example/documentation credentials**: a credential appearing inside prose in `README.md`:
```markdown
## Setup

Configure your API key:

    export STRIPE_KEY='sk_tes...'   # Example only
```

**Test fixture credentials**
```python
# File: tests/conftest.py
@pytest.fixture
def test_user():
    return User(username='test_user', password='test_pass')  # OK - test scope
```
