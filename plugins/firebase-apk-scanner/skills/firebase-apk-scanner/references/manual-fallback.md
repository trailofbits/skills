# Manual Testing (If Scanner Fails)

If the scanner script is unavailable or fails, perform manual extraction and testing:

### Extract Configuration

Search for Firebase config in decompiled APK:

```bash
# Decompile
apktool d -f -o ./decompiled "$ARGUMENTS"

# Find google-services.json
find ./decompiled -name "google-services.json"

# Search XML resources
grep -r "firebaseio.com\|appspot.com\|AIza" ./decompiled/res/

# Search assets (hybrid apps)
grep -r "firebaseio.com\|AIza" ./decompiled/assets/
```

### Test Endpoints

Once you have the PROJECT_ID and API_KEY:

**Authentication:**
```bash
# Test open signup
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!","returnSecureToken":true}' \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY"

# Test anonymous auth
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}' \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY"
```

**Database:**
```bash
# Realtime Database read
curl -s "https://PROJECT_ID.firebaseio.com/.json"

# Firestore read
curl -s "https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents"
```

**Storage:**
```bash
# List bucket
curl -s "https://firebasestorage.googleapis.com/v0/b/PROJECT_ID.appspot.com/o"
```

**Remote Config:**
```bash
curl -s -H "x-goog-api-key: API_KEY" \
  "https://firebaseremoteconfig.googleapis.com/v1/projects/PROJECT_ID/remoteConfig"
```
