# Reusable Frida Script Patterns

## Pattern: Function Argument Logger

Log all calls to a function with typed argument decoding.

```javascript
function hookExport(moduleName, funcName, argSpec) {
  const addr = Module.findExportByName(moduleName, funcName);
  if (!addr) {
    console.log(`[!] ${funcName} not found in ${moduleName}`);
    return;
  }

  Interceptor.attach(addr, {
    onEnter(args) {
      const decoded = argSpec.map((spec, i) => {
        switch (spec.type) {
          case 'utf8':  return args[i].readUtf8String();
          case 'int':   return args[i].toInt32();
          case 'uint':  return args[i].toUInt32();
          case 'ptr':   return args[i];
          case 'bool':  return args[i].toInt32() !== 0;
          default:      return args[i];
        }
      });
      console.log(`${funcName}(${decoded.map((v, i) =>
        `${argSpec[i].name}=${v}`).join(', ')})`);
    },
    onLeave(retval) {
      console.log(`  → ${retval}`);
    }
  });
}

// Usage:
hookExport(null, 'open', [
  { name: 'path', type: 'utf8' },
  { name: 'flags', type: 'int' }
]);
```

## Pattern: Module Export Dumper

Enumerate and categorize all exports from a module.

```javascript
function dumpModule(moduleName) {
  const mod = Process.findModuleByName(moduleName);
  if (!mod) {
    console.log(`[!] Module ${moduleName} not found`);
    return;
  }

  console.log(`\n=== ${mod.name} ===`);
  console.log(`Base: ${mod.base}  Size: ${mod.size}`);

  const exports = mod.enumerateExports();
  const functions = exports.filter(e => e.type === 'function');
  const variables = exports.filter(e => e.type === 'variable');

  console.log(`\nFunctions (${functions.length}):`);
  functions.forEach(e => console.log(`  ${e.name} @ ${e.address}`));

  console.log(`\nVariables (${variables.length}):`);
  variables.forEach(e => console.log(`  ${e.name} @ ${e.address}`));
}

// Usage:
dumpModule('Security');
```

## Pattern: Memory Scanner

Search process memory for byte patterns or strings.

```javascript
function scanForString(searchString) {
  const pattern = searchString.split('')
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join(' ');

  Process.enumerateRanges('r--').forEach(range => {
    try {
      Memory.scan(range.base, range.size, pattern, {
        onMatch(address, size) {
          console.log(`Found "${searchString}" at ${address}`);
          console.log(hexdump(address, { length: 64 }));
        },
        onComplete() {}
      });
    } catch (e) {
      // Skip unreadable ranges
    }
  });
}

// Usage:
scanForString('password');
```

## Pattern: Crypto API Monitor

Monitor CommonCrypto operations (encryption, hashing, HMAC).

```javascript
const CCOperation = { 0: 'Encrypt', 1: 'Decrypt' };
const CCAlgorithm = {
  0: 'AES', 1: 'DES', 2: '3DES', 3: 'CAST', 4: 'RC4', 5: 'RC2', 6: 'Blowfish'
};

Interceptor.attach(Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt'), {
  onEnter(args) {
    const op = args[0].toInt32();
    const alg = args[1].toInt32();
    const keyLen = args[3].toInt32();

    console.log(`CCCrypt: ${CCOperation[op] || op} with ${CCAlgorithm[alg] || alg}`);
    console.log(`  Key (${keyLen} bytes): ${hexdump(args[2], { length: keyLen })}`);
    console.log(`  Input length: ${args[5].toInt32()}`);
  },
  onLeave(retval) {
    console.log(`  Status: ${retval.toInt32()}`);
  }
});

// Hash operations
['CC_SHA1', 'CC_SHA256', 'CC_SHA512', 'CC_MD5'].forEach(func => {
  const addr = Module.findExportByName('libcommonCrypto.dylib', func);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter(args) {
        const len = args[1].toInt32();
        console.log(`${func}: ${len} bytes`);
        if (len < 256) {
          console.log(hexdump(args[0], { length: Math.min(len, 64) }));
        }
      }
    });
  }
});
```

## Pattern: Network Traffic Monitor

Intercept URL requests and responses.

```javascript
// NSURLSession requests
const resolver = new ApiResolver('objc');

resolver.enumerateMatches(
  '-[NSURLSession dataTaskWithRequest:completionHandler:]'
).forEach(match => {
  Interceptor.attach(match.address, {
    onEnter(args) {
      const request = new ObjC.Object(args[2]);
      const url = request.URL().absoluteString().toString();
      const method = request.HTTPMethod().toString();

      console.log(`\n[HTTP] ${method} ${url}`);

      // Log headers
      const headers = request.allHTTPHeaderFields();
      if (headers !== null) {
        const keys = headers.allKeys();
        for (let i = 0; i < keys.count().valueOf(); i++) {
          const key = keys.objectAtIndex_(i);
          console.log(`  ${key}: ${headers.objectForKey_(key)}`);
        }
      }

      // Log body
      const body = request.HTTPBody();
      if (body !== null && body.length() > 0) {
        const bodyStr = body.bytes().readUtf8String(body.length());
        console.log(`  Body: ${bodyStr}`);
      }
    }
  });
});
```

## Pattern: File I/O Monitor

Track file system access by a process.

```javascript
['open', 'openat'].forEach(func => {
  const addr = Module.findExportByName('libSystem.B.dylib', func);
  if (!addr) return;

  Interceptor.attach(addr, {
    onEnter(args) {
      const pathIdx = func === 'openat' ? 1 : 0;
      this.path = args[pathIdx].readUtf8String();
    },
    onLeave(retval) {
      const fd = retval.toInt32();
      if (fd >= 0) {
        console.log(`${func}("${this.path}") = fd ${fd}`);
      }
    }
  });
});

// Also monitor reads/writes on interesting fds
const trackedFds = new Set();

Interceptor.attach(Module.findExportByName(null, 'read'), {
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.buf = args[1];
    this.size = args[2].toInt32();
  },
  onLeave(retval) {
    const bytesRead = retval.toInt32();
    if (trackedFds.has(this.fd) && bytesRead > 0) {
      console.log(`read(fd=${this.fd}, ${bytesRead} bytes)`);
      console.log(hexdump(this.buf, { length: Math.min(bytesRead, 128) }));
    }
  }
});
```

## Pattern: ObjC Class Dumper

Dump all methods and properties of a class hierarchy.

```javascript
function dumpClass(className) {
  if (!ObjC.classes.hasOwnProperty(className)) {
    console.log(`[!] Class ${className} not found`);
    return;
  }

  const cls = ObjC.classes[className];
  console.log(`\n=== ${className} ===`);
  console.log(`Super: ${cls.$superClass?.$className || 'none'}`);
  console.log(`Protocols: ${cls.$protocols ? Object.keys(cls.$protocols).join(', ') : 'none'}`);

  console.log(`\nOwn Methods (${cls.$ownMethods.length}):`);
  cls.$ownMethods.sort().forEach(m => console.log(`  ${m}`));

  console.log(`\nOwn Properties:`);
  if (cls.$ownProperties) {
    cls.$ownProperties.forEach(p => console.log(`  ${p}`));
  }
}

// Dump a class and its superclasses
function dumpHierarchy(className) {
  let current = className;
  while (current && ObjC.classes.hasOwnProperty(current)) {
    dumpClass(current);
    const superCls = ObjC.classes[current].$superClass;
    current = superCls ? superCls.$className : null;
    if (current === 'NSObject') break;  // Stop at NSObject
  }
}

// Usage:
dumpClass('AppDelegate');
```

## Pattern: Method Swizzling (Replace Implementation)

Replace an ObjC method's implementation entirely:

```javascript
function swizzle(className, methodName, newImpl) {
  const cls = ObjC.classes[className];
  const method = cls[methodName];
  const original = method.implementation;

  method.implementation = ObjC.implement(method, function(handle, selector) {
    // 'this' context is not available; use handle for self
    const self = new ObjC.Object(handle);
    const args = Array.from(arguments).slice(2);
    return newImpl(self, original, ...args);
  });

  return original;  // Return original for potential restoration
}

// Usage: Make a method always return YES
swizzle('SecurityManager', '- isDeviceTrusted', function(self, original) {
  console.log(`isDeviceTrusted called on ${self}`);
  return ptr(1);  // YES
});
```

## Pattern: Batch Hook with Filtering

Hook multiple methods matching criteria, with structured output.

```javascript
function batchHook(pattern, { logArgs = false, logRetval = false, filter = null } = {}) {
  const resolver = new ApiResolver('objc');
  const matches = resolver.enumerateMatches(pattern);

  if (filter) {
    matches = matches.filter(filter);
  }

  console.log(`[*] Hooking ${matches.length} methods matching "${pattern}"`);

  matches.forEach(match => {
    try {
      Interceptor.attach(match.address, {
        onEnter(args) {
          const msg = [`[>] ${match.name}`];
          if (logArgs) {
            const self = new ObjC.Object(args[0]);
            msg.push(`  self: ${self.$className}`);
          }
          console.log(msg.join('\n'));
        },
        onLeave(retval) {
          if (logRetval && !retval.isNull()) {
            try {
              const obj = new ObjC.Object(retval);
              console.log(`[<] ${match.name} → ${obj}`);
            } catch (e) {
              console.log(`[<] ${match.name} → ${retval}`);
            }
          }
        }
      });
    } catch (e) {
      console.log(`[!] Failed to hook ${match.name}: ${e.message}`);
    }
  });
}

// Usage:
batchHook('-[*ViewController viewDid*]', { logRetval: false });
batchHook('-[NSUserDefaults *forKey:]', { logArgs: true, logRetval: true });
```

## Pattern: Stalker Trace with Module Filter

Trace execution while excluding noisy system libraries.

```javascript
function traceFiltered(threadId, targetModules, durationMs) {
  // Exclude everything except target modules
  Process.enumerateModules().forEach(mod => {
    if (!targetModules.includes(mod.name)) {
      Stalker.exclude(mod);
    }
  });

  const calls = {};

  Stalker.follow(threadId, {
    events: { call: true },
    onReceive(events) {
      const parsed = Stalker.parse(events, { annotate: true, stringify: true });
      parsed.forEach(event => {
        if (event[0] === 'call') {
          const target = event[2];
          calls[target] = (calls[target] || 0) + 1;
        }
      });
    }
  });

  setTimeout(() => {
    Stalker.unfollow(threadId);
    Stalker.flush();
    console.log('\n=== Call Summary ===');
    Object.entries(calls)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 50)
      .forEach(([addr, count]) => {
        const sym = DebugSymbol.fromAddress(ptr(addr));
        console.log(`  ${count}x  ${sym}`);
      });
  }, durationMs);
}

// Usage: Trace only the app's own code for 3 seconds
traceFiltered(Process.getCurrentThreadId(), ['MyApp'], 3000);
```
