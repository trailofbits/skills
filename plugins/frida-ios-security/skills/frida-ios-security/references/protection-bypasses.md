# Protection Bypass Patterns

Detailed Frida scripts for testing each iOS security domain. These are assessment scripts — they test whether controls resist bypass, not pre-built exploitation tools.

## Network Security: Certificate Pinning

### NSURLSession Delegate Pinning

The most common pinning implementation. The app provides a delegate that handles `URLSession:didReceiveChallenge:completionHandler:`.

```javascript
// Discover pinning implementations
const resolver = new ApiResolver('objc');
resolver.enumerateMatches(
  '-[* URLSession:didReceiveChallenge:completionHandler:]'
).forEach(match => {
  console.log(`Pinning delegate: ${match.name} @ ${match.address}`);
});
```

```javascript
// Test bypass: override challenge handler to accept all certificates
const resolver = new ApiResolver('objc');
resolver.enumerateMatches(
  '-[* URLSession:didReceiveChallenge:completionHandler:]'
).forEach(match => {
  Interceptor.attach(match.address, {
    onEnter(args) {
      const challenge = new ObjC.Object(args[3]);
      const completionHandler = new ObjC.Block(args[4]);

      const NSURLSessionAuthChallengeUseCredential = 0;
      const serverTrust = challenge.protectionSpace().serverTrust();
      const credential = ObjC.classes.NSURLCredential
        .credentialForTrust_(serverTrust);

      completionHandler.implementation(
        NSURLSessionAuthChallengeUseCredential, credential
      );

      console.log(`[BYPASS] Certificate pinning bypassed for: ${
        challenge.protectionSpace().host()}`);
    }
  });
});
```

**Verification:** After running the bypass, proxy the device through Burp/mitmproxy. If you can intercept HTTPS traffic that was previously failing, the pinning is bypassable.

### TrustKit Pinning

```javascript
// Detect TrustKit
if (ObjC.classes.hasOwnProperty('TSKPinningValidator')) {
  console.log('[FOUND] TrustKit pinning detected');

  // List pinning configuration
  const config = ObjC.classes.TrustKit.alloc().initWithConfiguration_({});
  console.log(`Config: ${config}`);
}

// Bypass TrustKit validation
const TSKClass = ObjC.classes.TSKPinningValidator;
if (TSKClass) {
  Interceptor.attach(
    TSKClass['- evaluateTrust:forHostname:'].implementation, {
      onLeave(retval) {
        retval.replace(ptr(0));  // TSKTrustDecisionShouldAllowConnection
        console.log('[BYPASS] TrustKit validation bypassed');
      }
    }
  );
}
```

### SecTrust Direct Validation

Some apps call Security framework directly:

```javascript
// Hook SecTrustEvaluateWithError (modern API)
const secTrustEval = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
if (secTrustEval) {
  Interceptor.attach(secTrustEval, {
    onEnter(args) {
      this.errorPtr = args[1];
    },
    onLeave(retval) {
      if (retval.toInt32() === 0) {  // Evaluation failed
        retval.replace(ptr(1));       // Force success
        if (!this.errorPtr.isNull()) {
          this.errorPtr.writePointer(ptr(0));  // Clear error
        }
        console.log('[BYPASS] SecTrustEvaluateWithError bypassed');
      }
    }
  });
}
```

## Data Storage: Keychain Analysis

### Monitor Keychain Operations

```javascript
// Monitor all Keychain additions
Interceptor.attach(Module.findExportByName('Security', 'SecItemAdd'), {
  onEnter(args) {
    const query = new ObjC.Object(args[0]);
    const dict = query.description().toString();

    // Extract protection class
    const accessible = query.objectForKey_('pdmn');
    console.log(`\n[KEYCHAIN ADD]`);
    console.log(`  Attributes: ${dict}`);
    if (accessible) {
      console.log(`  Protection: ${accessible}`);
    }
  },
  onLeave(retval) {
    console.log(`  Result: ${retval.toInt32()}`);
  }
});

// Monitor Keychain reads
Interceptor.attach(Module.findExportByName('Security', 'SecItemCopyMatching'), {
  onEnter(args) {
    const query = new ObjC.Object(args[0]);
    console.log(`\n[KEYCHAIN READ]`);
    console.log(`  Query: ${query.description()}`);
    this.resultPtr = args[1];
  },
  onLeave(retval) {
    if (retval.toInt32() === 0 && !this.resultPtr.isNull()) {
      try {
        const result = new ObjC.Object(this.resultPtr.readPointer());
        console.log(`  Found: ${result.$className}`);
      } catch (e) {
        console.log(`  Found: (raw data)`);
      }
    }
  }
});
```

### Check Protection Classes

Keychain protection class determines when items are accessible:

| Class Constant | `pdmn` Value | When Accessible | Risk |
|---------------|-------------|-----------------|------|
| `kSecAttrAccessibleWhenUnlocked` | `ak` | Only when unlocked | Low |
| `kSecAttrAccessibleAfterFirstUnlock` | `ck` | After first unlock until reboot | Medium |
| `kSecAttrAccessibleAlways` | `dk` | Always, even when locked | **CRITICAL** |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | `akpu` | Only with passcode set | Low |

```javascript
// Flag items with weak protection
Interceptor.attach(Module.findExportByName('Security', 'SecItemAdd'), {
  onEnter(args) {
    const query = new ObjC.Object(args[0]);
    const accessible = query.objectForKey_('pdmn');
    if (accessible) {
      const val = accessible.toString();
      if (val === 'dk' || val === 'dku') {
        console.log(`[FINDING] Keychain item with kSecAttrAccessibleAlways!`);
        console.log(`  Query: ${query.description()}`);
      }
    }
  }
});
```

### NSUserDefaults Secrets Detection

```javascript
// Monitor NSUserDefaults writes for secrets
const sensitiveKeys = ['token', 'password', 'secret', 'key', 'auth',
                       'credential', 'session', 'jwt', 'api_key', 'apikey'];

Interceptor.attach(
  ObjC.classes.NSUserDefaults['- setObject:forKey:'].implementation, {
    onEnter(args) {
      const key = new ObjC.Object(args[3]).toString().toLowerCase();
      const value = new ObjC.Object(args[2]);
      if (sensitiveKeys.some(s => key.includes(s))) {
        console.log(`[FINDING] Sensitive data in NSUserDefaults!`);
        console.log(`  Key: ${key}`);
        console.log(`  Value type: ${value.$className}`);
        console.log(`  Value: ${value.toString().substring(0, 100)}`);
      }
    }
  }
);
```

## Authentication: Biometric Bypass

### LAContext (Touch ID / Face ID)

```javascript
// Monitor biometric authentication requests
Interceptor.attach(
  ObjC.classes.LAContext['- evaluatePolicy:localizedReason:reply:'].implementation,
  {
    onEnter(args) {
      const policy = args[2].toInt32();
      const reason = new ObjC.Object(args[3]).toString();
      console.log(`\n[BIOMETRIC] Authentication requested`);
      console.log(`  Policy: ${policy === 1 ? 'BiometryAny' : 'BiometryCurrentSet'}`);
      console.log(`  Reason: ${reason}`);

      // Capture the reply block for bypass testing
      this.replyBlock = new ObjC.Block(args[4]);
    }
  }
);
```

```javascript
// Bypass: Force biometric success
Interceptor.attach(
  ObjC.classes.LAContext['- evaluatePolicy:localizedReason:reply:'].implementation,
  {
    onEnter(args) {
      const reason = new ObjC.Object(args[3]).toString();
      const replyBlock = new ObjC.Block(args[4]);

      // Call the reply block with success=YES, error=nil
      replyBlock.implementation(1, ptr(0));
      console.log(`[BYPASS] Biometric auth bypassed for: ${reason}`);
    }
  }
);
```

**Verification:** After bypass, check whether the app grants access to protected functionality. If biometric auth only gates a UI element but sensitive operations don't re-verify server-side, the finding severity escalates.

## Anti-Tampering: Jailbreak Detection

### Common Detection Patterns

```javascript
// File existence checks — the most common jailbreak detection
const jailbreakPaths = [
  '/Applications/Cydia.app', '/usr/sbin/sshd', '/bin/bash',
  '/etc/apt', '/private/var/lib/apt/', '/usr/bin/ssh',
  '/Library/MobileSubstrate', '/var/cache/apt',
  '/var/lib/cydia', '/var/tmp/cydia.log',
  '/usr/libexec/sftp-server', '/usr/share/terminfo',
  '/private/var/stash', '/usr/lib/libjailbreak.dylib'
];

// Monitor and bypass file checks
['access', 'stat', 'lstat', 'open'].forEach(func => {
  const addr = Module.findExportByName(null, func);
  if (!addr) return;

  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        this.path = args[0].readUtf8String();
      } catch (e) {
        this.path = null;
      }
    },
    onLeave(retval) {
      if (this.path && jailbreakPaths.some(p => this.path.includes(p))) {
        retval.replace(ptr(-1));
        console.log(`[BYPASS] JB file check: ${this.path}`);
      }
    }
  });
});
```

```javascript
// canOpenURL checks (Cydia URL scheme)
Interceptor.attach(
  ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
    onEnter(args) {
      this.url = new ObjC.Object(args[2]).absoluteString().toString();
    },
    onLeave(retval) {
      if (this.url.includes('cydia://') || this.url.includes('sileo://')) {
        retval.replace(ptr(0));
        console.log(`[BYPASS] JB URL scheme check: ${this.url}`);
      }
    }
  }
);
```

```javascript
// Fork-based detection (fork succeeds on jailbroken devices)
Interceptor.attach(Module.findExportByName(null, 'fork'), {
  onLeave(retval) {
    retval.replace(ptr(-1));  // Return failure (non-jailbroken behavior)
    console.log('[BYPASS] fork() jailbreak detection bypassed');
  }
});
```

### Debugger Detection

```javascript
// ptrace anti-debug
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
  onEnter(args) {
    const request = args[0].toInt32();
    if (request === 31) {  // PT_DENY_ATTACH
      console.log('[BYPASS] PT_DENY_ATTACH detected and bypassed');
      args[0] = ptr(0);  // Change to PT_TRACE_ME (harmless)
    }
  }
});

// sysctl-based debugger detection
Interceptor.attach(Module.findExportByName(null, 'sysctl'), {
  onEnter(args) {
    this.mib = args[0];
    this.oldp = args[2];
  },
  onLeave(retval) {
    try {
      const mib0 = this.mib.readInt();
      const mib1 = this.mib.add(4).readInt();
      const mib2 = this.mib.add(8).readInt();
      if (mib0 === 1 && mib1 === 14 && mib2 === 1) {  // CTL_KERN, KERN_PROC, KERN_PROC_PID
        // Clear P_TRACED flag in kp_proc.p_flag
        const flagPtr = this.oldp.add(32);  // offset to p_flag
        const flags = flagPtr.readInt();
        flagPtr.writeInt(flags & ~0x800);  // Clear P_TRACED
        console.log('[BYPASS] sysctl debugger detection bypassed');
      }
    } catch (e) {}
  }
});
```

## Platform Security: URL Scheme Testing

```javascript
// Monitor incoming URL scheme invocations
Interceptor.attach(
  ObjC.classes.UIApplicationDelegate
    ? ObjC.classes.AppDelegate['- application:openURL:options:']?.implementation
    : null,
  {
    onEnter(args) {
      if (args[3]) {
        const url = new ObjC.Object(args[3]);
        console.log(`[URL SCHEME] Opened: ${url.absoluteString()}`);
        console.log(`  Scheme: ${url.scheme()}`);
        console.log(`  Host: ${url.host()}`);
        console.log(`  Path: ${url.path()}`);
        console.log(`  Query: ${url.query()}`);
      }
    }
  }
);
```

```javascript
// Monitor pasteboard access
Interceptor.attach(
  ObjC.classes.UIPasteboard['+ generalPasteboard'].implementation, {
    onLeave(retval) {
      const pb = new ObjC.Object(retval);
      const str = pb.string();
      if (str) {
        console.log(`[PASTEBOARD] Read: ${str.toString().substring(0, 200)}`);
      }
    }
  }
);

// Monitor pasteboard writes
Interceptor.attach(
  ObjC.classes.UIPasteboard['- setString:'].implementation, {
    onEnter(args) {
      const str = new ObjC.Object(args[2]).toString();
      console.log(`[PASTEBOARD] Write: ${str.substring(0, 200)}`);
    }
  }
);
```
