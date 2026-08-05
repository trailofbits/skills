# Debug and Introspection Defaults

**Report when:** Internal detail reaches a response, a listening port, or a log a lower-privileged party can read, whether it is gated by a flag that defaults to on, or simply unconditional (a stack trace or driver message written straight into an error response, with no flag at all).

**Skip when:** Log-verbosity-only flags with no user-facing output. Debug servers bound to loopback and off by default.

The finding needs both halves: enabled-by-default *and* an exposure path. A verbose logger that writes to a root-only file is neither.

## VULNERABLE - Report These

**Stack traces in API responses**
```python
# File: app.py
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc()  # Leaks internal paths, library versions
    }), 500
```
**Why vulnerable:** Exposes internal implementation details to attackers.

**GraphQL introspection enabled**
```javascript
// File: server.js
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,  // Enabled in production
  playground: true
});
```
**Why vulnerable:** Attackers can discover entire API schema, including admin-only fields.

**Verbose error messages**
```java
// File: UserController.java
catch (SQLException e) {
    return ResponseEntity.status(500).body(
        "Database error: " + e.getMessage()  // Leaks table names, constraints
    );
}
```
**Why vulnerable:** SQL error messages reveal database structure.

## SECURE - Skip These

**Debug features in logging only**
```python
# File: app.py
@app.errorhandler(Exception)
def handle_error(error):
    logger.exception('Request failed', exc_info=error)  # Logs full trace
    return jsonify({'error': 'Internal server error'}), 500  # Generic to user
```

**Environment-aware debug settings**
```javascript
// File: server.js
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  playground: process.env.NODE_ENV !== 'production'
});
```

**Generic user-facing errors**
```java
// File: UserController.java
catch (SQLException e) {
    logger.error("Database error", e);  // Full details to logs
    return ResponseEntity.status(500).body("Unable to process request");  // Generic
}
```
