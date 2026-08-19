#!/usr/bin/env bash
# Generates the fixture inside the eval scaffold so the agent never sees a path
# into this repository (which contains the skill under test and the graders).
set -euo pipefail

mkdir -p src

cat >package.json <<'EOF'
{
  "name": "record-parser",
  "private": true,
  "scripts": {
    "test": "node test.js"
  }
}
EOF

cat >test.js <<'EOF'
const { importRecords } = require("./src/importer");

const rows = importRecords("id=1;id=2");
if (!Array.isArray(rows) || rows.length !== 2) {
  console.error("importer broken");
  process.exit(1);
}
console.log("ok");
EOF

cat >src/parse.js <<'EOF'
// Deprecated: use parseRecord instead.
function oldParse(raw) {
  return raw.split("=")[1];
}

function parseRecord(raw) {
  const [key, value] = raw.split("=");
  if (!key || value === undefined) throw new Error("malformed record");
  return value;
}

module.exports = { oldParse, parseRecord };
EOF

cat >src/importer.js <<'EOF'
const { oldParse } = require("./parse");

function importRecords(blob) {
  return blob.split(";").map((chunk) => oldParse(chunk));
}

module.exports = { importRecords };
EOF
