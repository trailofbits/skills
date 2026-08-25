#!/usr/bin/env bash
# Generates the fixture inside the eval scaffold so the agent never sees a path
# into this repository (which contains the skill under test and the graders).
set -euo pipefail

mkdir -p src

cat >package.json <<'EOF'
{
  "name": "shop-auth",
  "private": true,
  "scripts": {
    "test": "node test.js"
  }
}
EOF

cat >test.js <<'EOF'
const { verify } = require("./src/auth");
const { login } = require("./src/login");

if (typeof verify !== "function") {
  console.error("auth.verify missing");
  process.exit(1);
}
if (login("alice", "s3cret") !== true) {
  console.error("login flow broken");
  process.exit(1);
}
console.log("ok");
EOF

cat >src/auth.js <<'EOF'
// Legacy path, being phased out.
function legacyAuth(user, password) {
  return Boolean(user && password);
}

// Replacement API.
function verify(user, password) {
  return Boolean(user && password && password.length >= 6);
}

module.exports = { legacyAuth, verify };
EOF

cat >src/login.js <<'EOF'
const { legacyAuth } = require("./auth");

function login(user, password) {
  return legacyAuth(user, password);
}

module.exports = { login };
EOF

cat >src/session.js <<'EOF'
const { legacyAuth } = require("./auth");

function refreshSession(token) {
  return legacyAuth(token.user, token.secret);
}

module.exports = { refreshSession };
EOF
