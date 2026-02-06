# iOS-Specific Frida Guide

## Platform Requirements

| Scenario | Requirements | Frida Component |
|----------|-------------|-----------------|
| Jailbroken device | frida-server installed via package manager | frida-server |
| Non-jailbroken (own app) | Developer profile, Xcode | Gadget (auto-injected) |
| Non-jailbroken (third-party app) | Re-signed IPA with Gadget embedded | Gadget (manual embed) |

## Jailbroken Device Setup

### Install frida-server

Add the Frida repository to your package manager (Cydia, Sileo, Zebra):

```text
Repository URL: https://build.frida.re
```

Install the `Frida` package. This places `frida-server` in the device's PATH.

### Verify

```bash
# From your computer (USB connection)
frida-ps -U
```

If no device appears, ensure:
1. USB cable is connected (not WiFi)
2. Trust prompt was accepted on the device
3. `frida-server` is running: `ssh root@device "frida-server &"`

### Connection Methods

| Method | Flag | When to Use |
|--------|------|-------------|
| USB | `-U` | Default, most reliable |
| Network | `-H <ip>:27042` | When USB unavailable (frida-server listens on 27042) |
| Device ID | `-D <udid>` | Multiple devices connected |

## Non-Jailbroken: Frida Gadget

Frida Gadget is a shared library you embed in an app. When the app loads, Gadget initializes Frida's runtime automatically.

### Automatic Injection (Your Own Apps)

For apps you build with Xcode:
1. Frida downloads Gadget to `~/.cache/frida/gadget-ios.dylib` automatically
2. Attach via `frida -U -f com.yourcompany.app`
3. Frida handles injection through the debug interface

### Manual Embedding (Third-Party Apps)

For apps you don't control:

1. **Obtain the IPA** and extract it
2. **Download Gadget**: Get `frida-gadget-{version}-ios-universal.dylib` from Frida releases
3. **Copy Gadget** into the app's Frameworks directory:
   ```bash
   cp FridaGadget.dylib Payload/App.app/Frameworks/
   ```
4. **Patch the binary** to load Gadget:
   ```bash
   insert_dylib --strip-codesig --inplace \
     @executable_path/Frameworks/FridaGadget.dylib \
     Payload/App.app/AppBinary
   ```
5. **Re-sign** the app with your developer certificate
6. **Install** via Xcode, `ios-deploy`, or similar

### Gadget Configuration

Place a config file next to the Gadget dylib (`FridaGadget.config`):

```json
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_load": "wait"
  },
  "code_signing": "required"
}
```

**Key settings:**

| Setting | Values | Purpose |
|---------|--------|---------|
| `interaction.type` | `listen`, `script`, `connect` | How Gadget operates |
| `interaction.on_load` | `wait`, `resume` | Whether to pause on load |
| `code_signing` | `required`, `optional` | Set to `required` for non-jailbroken devices |
| `runtime` | `default`, `qjs`, `v8` | JavaScript engine selection |

## iOS-Specific Hooking Patterns

### Certificate Pinning Bypass

Certificate pinning typically runs early. Use spawn mode:

```javascript
// Spawn mode: frida -U -f com.example.app -l bypass.js

// Hook NSURLSession delegate method
const resolver = new ApiResolver('objc');
resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]')
  .forEach(match => {
    Interceptor.attach(match.address, {
      onEnter(args) {
        // args[4] = completionHandler block
        const completionHandler = new ObjC.Block(args[4]);
        const NSURLSessionAuthChallengeUseCredential = 0;
        const serverTrust = new ObjC.Object(args[3])
          .protectionSpace().serverTrust();
        const credential = ObjC.classes.NSURLCredential
          .credentialForTrust_(serverTrust);
        completionHandler.implementation(
          NSURLSessionAuthChallengeUseCredential, credential
        );
      }
    });
  });
```

### Jailbreak Detection Bypass

Common checks to intercept:

```javascript
// File existence checks
Interceptor.attach(Module.findExportByName(null, 'access'), {
  onEnter(args) {
    this.path = args[0].readUtf8String();
  },
  onLeave(retval) {
    const jbPaths = ['/Applications/Cydia.app', '/bin/bash',
                     '/usr/sbin/sshd', '/etc/apt', '/private/var/stash'];
    if (jbPaths.some(p => this.path?.includes(p))) {
      retval.replace(ptr(-1));  // Return "not found"
    }
  }
});

// canOpenURL checks for Cydia
Interceptor.attach(
  ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
    onEnter(args) {
      this.url = new ObjC.Object(args[2]).absoluteString().toString();
    },
    onLeave(retval) {
      if (this.url.includes('cydia://')) {
        retval.replace(ptr(0));  // Return NO
      }
    }
  }
);
```

### Keychain Access Monitoring

```javascript
// Monitor SecItemCopyMatching
Interceptor.attach(Module.findExportByName('Security', 'SecItemCopyMatching'), {
  onEnter(args) {
    const query = new ObjC.Object(args[0]);
    console.log('Keychain query:', query.toString());
  },
  onLeave(retval) {
    console.log('SecItemCopyMatching result:', retval.toInt32());
  }
});
```

## iOS Code Signing Considerations

- **Entitlements matter**: Apps without `get-task-allow` cannot be debugged/instrumented on stock devices
- **Re-signing strips entitlements**: When embedding Gadget, preserve original entitlements and add `get-task-allow`
- **Provisioning profiles**: The re-signed app must match a valid provisioning profile on the device
- **App Store binaries**: These are encrypted (FairPlay DRM) — decrypt before analyzing

## Spawn vs Attach on iOS

| Factor | Spawn (`-f bundle.id`) | Attach (`-U name`) |
|--------|----------------------|-------------------|
| Hooks `+[load]` methods | Yes | No — already executed |
| Hooks `didFinishLaunching` | Yes | No — already executed |
| Jailbreak detection bypass | Essential — detection runs early | Too late |
| Certificate pinning bypass | Essential — pinning set up early | Depends on implementation |
| Runtime method inspection | Full lifecycle | Current state only |
