# Manual Firebase APK Testing Fallback

Use this when the bundled scanner is unavailable or produces no report, or to
test projects and regions the scanner did not cover. Confirm that testing is
authorized before making requests. Report failures, gaps, and the manual steps
actually completed.

## Extract configuration

```bash
apktool d -f -o ./decompiled "$ARGUMENTS"
find ./decompiled -name "google-services.json"
grep -r "firebaseio.com\|appspot.com\|AIza" ./decompiled/res/
grep -r "firebaseio.com\|AIza" ./decompiled/assets/
```

## Test discovered endpoints

Replace `PROJECT_ID` and `API_KEY` with extracted values. Use only against
authorized targets and clean up any test data you create.

### Authentication

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!","returnSecureToken":true}' \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY"

curl -s -X POST -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}' \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY"
```

### Data and storage

Save any successful anonymous-authentication ID token and use it for authorized
authenticated-bypass testing as described in the main skill's vulnerability
reference. Record unauthenticated and token-authenticated results separately.

```bash
curl -s "https://PROJECT_ID.firebaseio.com/.json"
curl -s "https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents"
curl -s "https://firebasestorage.googleapis.com/v0/b/PROJECT_ID.appspot.com/o"
```

### Remote Config

```bash
curl -s -H "x-goog-api-key: API_KEY" \
  "https://firebaseremoteconfig.googleapis.com/v1/projects/PROJECT_ID/remoteConfig"
```

### Cloud Functions

Test each discovered function in each relevant region. The bundled scanner only
tests `us-central1`, so do not treat its result as coverage of other regions.

```bash
curl -s "https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME"
```

## Severity guide

- **Critical:** unauthenticated database read/write, storage write, or open
  signup on a private app.
- **High:** anonymous authentication, bucket listing, or collection enumeration.
- **Medium:** email enumeration, exposed Cloud Functions, or Remote Config.
- **Low:** information disclosure without sensitive data.

For every request, retain the URL, HTTP status, and a minimal response excerpt as
evidence. Test every discovered project/API-key pair that is in scope, and state
which project or region could not be tested.
