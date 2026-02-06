# Runtime Data Extraction Patterns

Scripts for extracting and inspecting sensitive data during iOS security assessments. Use these to verify whether protections adequately guard sensitive information.

## Keychain Dump

Extract all accessible Keychain items to assess protection classes and stored data.

```javascript
function dumpKeychain() {
  const secClasses = [
    'genp',  // kSecClassGenericPassword
    'inet',  // kSecClassInternetPassword
    'cert',  // kSecClassCertificate
    'keys',  // kSecClassKey
    'idnt'   // kSecClassIdentity
  ];

  const classNames = {
    genp: 'GenericPassword',
    inet: 'InternetPassword',
    cert: 'Certificate',
    keys: 'CryptoKey',
    idnt: 'Identity'
  };

  secClasses.forEach(cls => {
    const query = ObjC.classes.NSMutableDictionary.alloc().init();
    query.setObject_forKey_(cls, 'class');
    query.setObject_forKey_(ObjC.classes.kCFBooleanTrue, 'r_Attributes');
    query.setObject_forKey_(ObjC.classes.kCFBooleanTrue, 'r_Data');
    query.setObject_forKey_('m_LimitAll', 'm_Limit');

    const resultPtr = Memory.alloc(Process.pointerSize);
    const SecItemCopyMatching = new NativeFunction(
      Module.findExportByName('Security', 'SecItemCopyMatching'),
      'int', ['pointer', 'pointer']
    );

    const ret = SecItemCopyMatching(query.handle, resultPtr);
    if (ret === 0) {
      const results = new ObjC.Object(resultPtr.readPointer());
      console.log(`\n=== ${classNames[cls]} (${results.count()} items) ===`);
      for (let i = 0; i < results.count().valueOf(); i++) {
        const item = results.objectAtIndex_(i);
        console.log(`\n  Item ${i}:`);
        console.log(`    Account: ${item.objectForKey_('acct') || 'N/A'}`);
        console.log(`    Service: ${item.objectForKey_('svce') || 'N/A'}`);
        console.log(`    Protection: ${item.objectForKey_('pdmn') || 'N/A'}`);
        const data = item.objectForKey_('v_Data');
        if (data) {
          try {
            const str = ObjC.classes.NSString.alloc()
              .initWithData_encoding_(data, 4);  // NSUTF8StringEncoding
            if (str) {
              console.log(`    Value: ${str.toString().substring(0, 100)}`);
            } else {
              console.log(`    Value: <${data.length()} bytes binary>`);
            }
          } catch (e) {
            console.log(`    Value: <${data.length()} bytes>`);
          }
        }
      }
    }
  });
}

dumpKeychain();
```

## Cookie and Session Extraction

```javascript
// Extract all HTTP cookies
function dumpCookies() {
  const cookieStore = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage();
  const cookies = cookieStore.cookies();

  console.log(`\n=== HTTP Cookies (${cookies.count()}) ===`);
  for (let i = 0; i < cookies.count().valueOf(); i++) {
    const cookie = cookies.objectAtIndex_(i);
    console.log(`\n  ${cookie.name()} = ${cookie.value()}`);
    console.log(`    Domain: ${cookie.domain()}`);
    console.log(`    Path: ${cookie.path()}`);
    console.log(`    Secure: ${cookie.isSecure()}`);
    console.log(`    HTTPOnly: ${cookie.isHTTPOnly()}`);
    console.log(`    Expires: ${cookie.expiresDate()}`);
  }
}

dumpCookies();
```

## Crypto Key Extraction

Monitor cryptographic key usage to verify proper key management.

```javascript
// Monitor SecKeyCreateRandomKey — key generation
const createKey = Module.findExportByName('Security', 'SecKeyCreateRandomKey');
if (createKey) {
  Interceptor.attach(createKey, {
    onEnter(args) {
      const params = new ObjC.Object(args[0]);
      console.log(`\n[CRYPTO] Key generation:`);
      console.log(`  Parameters: ${params.description()}`);
    },
    onLeave(retval) {
      if (!retval.isNull()) {
        console.log(`  Key created successfully`);
      }
    }
  });
}

// Monitor SecKeyEncrypt / SecKeyDecrypt
['SecKeyCreateEncryptedData', 'SecKeyCreateDecryptedData'].forEach(func => {
  const addr = Module.findExportByName('Security', func);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter(args) {
        const algorithm = new ObjC.Object(args[1]);
        console.log(`\n[CRYPTO] ${func}:`);
        console.log(`  Algorithm: ${algorithm}`);
        const data = new ObjC.Object(args[2]);
        console.log(`  Data length: ${data.length()}`);
      }
    });
  }
});
```

## File Protection Verification

```javascript
// Check data protection class on file writes
Interceptor.attach(
  ObjC.classes.NSFileManager['- createFileAtPath:contents:attributes:'].implementation,
  {
    onEnter(args) {
      const path = new ObjC.Object(args[2]).toString();
      const attrs = args[4].isNull() ? null : new ObjC.Object(args[4]);

      console.log(`\n[FILE] Create: ${path}`);
      if (attrs) {
        const protection = attrs.objectForKey_('NSFileProtectionKey');
        console.log(`  Protection: ${protection || 'NONE SET'}`);
        if (!protection || protection.toString() === 'NSFileProtectionNone') {
          console.log(`  [FINDING] File created with no protection!`);
        }
      } else {
        console.log(`  [FINDING] No attributes set — default protection only`);
      }
    }
  }
);

// Check protection on existing files
function checkFileProtection(path) {
  const fm = ObjC.classes.NSFileManager.defaultManager();
  const errorPtr = Memory.alloc(Process.pointerSize);
  errorPtr.writePointer(ptr(0));

  const attrs = fm.attributesOfItemAtPath_error_(path, errorPtr);
  if (attrs) {
    const protection = attrs.objectForKey_('NSFileProtectionKey');
    console.log(`${path}: ${protection || 'NO PROTECTION'}`);
  }
}
```

## Memory Inspection

```javascript
// Search for sensitive strings in process memory
function searchMemory(searchString) {
  const pattern = searchString.split('')
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join(' ');

  let found = 0;
  Process.enumerateRanges('r--').forEach(range => {
    try {
      Memory.scan(range.base, range.size, pattern, {
        onMatch(address, size) {
          found++;
          const context = address.sub(16);
          console.log(`\n[MEMORY] "${searchString}" found at ${address}`);
          console.log(hexdump(context, { length: 64 + searchString.length }));
        },
        onComplete() {}
      });
    } catch (e) {}
  });
  console.log(`\nTotal matches: ${found}`);
}

// Check if sensitive data persists after expected cleanup
// Usage: Log in, capture a token, log out, then:
// searchMemory('the-captured-token-value');
```

## Screenshot Protection

```javascript
// Check if app implements screenshot protection
// The applicationDidEnterBackground: delegate should obscure sensitive content

Interceptor.attach(
  ObjC.classes.UIApplication['- _reportAppVisibilityChanged:'].implementation || ptr(0),
  {
    onEnter(args) {
      console.log('[SCREENSHOT] App visibility changed');
      // Take a screenshot via the system to test protection
    }
  }
);

// Check for window-level protection
ObjC.schedule(ObjC.mainQueue, function() {
  const windows = ObjC.classes.UIApplication.sharedApplication().windows();
  for (let i = 0; i < windows.count().valueOf(); i++) {
    const window = windows.objectAtIndex_(i);
    console.log(`Window ${i}: secure=${window.isSecureTextEntry ? window.isSecureTextEntry() : 'N/A'}`);
  }
});
```

## Logging Sensitive Data Detection

```javascript
// Monitor NSLog for sensitive data leakage
Interceptor.attach(Module.findExportByName('Foundation', 'NSLog'), {
  onEnter(args) {
    const msg = new ObjC.Object(args[0]).toString();
    const sensitivePatterns = [
      /password/i, /token/i, /bearer/i, /secret/i,
      /credential/i, /session/i, /cookie/i, /authorization/i,
      /\b[A-Za-z0-9+/]{40,}\b/  // Base64-like strings (potential tokens)
    ];

    if (sensitivePatterns.some(p => p.test(msg))) {
      console.log(`[FINDING] Sensitive data in NSLog:`);
      console.log(`  ${msg.substring(0, 300)}`);
    }
  }
});

// Monitor os_log (modern logging)
Interceptor.attach(Module.findExportByName(null, '_os_log_impl'), {
  onEnter(args) {
    try {
      const formatStr = args[3].readUtf8String();
      if (formatStr && /password|token|secret|key/i.test(formatStr)) {
        console.log(`[FINDING] Sensitive format string in os_log: ${formatStr}`);
      }
    } catch (e) {}
  }
});
```
