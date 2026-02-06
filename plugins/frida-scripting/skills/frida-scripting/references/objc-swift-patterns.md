# Objective-C and Swift Runtime Patterns

## ObjC Runtime Fundamentals

Frida's `ObjC` module provides full access to the Objective-C runtime. Understanding message dispatch is critical for effective hooking.

### ObjC Method Dispatch

Every ObjC method call is `objc_msgSend(self, _cmd, arg1, arg2, ...)`:

| Argument Index | Contains | In Interceptor |
|---------------|----------|----------------|
| `args[0]` | `self` (the receiver object) | `new ObjC.Object(args[0])` |
| `args[1]` | `_cmd` (the selector) | `ObjC.selectorAsString(args[1])` |
| `args[2]` | First method argument | Type-dependent conversion |
| `args[3]` | Second method argument | Type-dependent conversion |

### Selector Naming Convention

Frida converts ObjC selectors by replacing `:` with `_`:

| ObjC Selector | Frida Property |
|--------------|----------------|
| `- (void)doSomething` | `['- doSomething']` |
| `- (void)doSomething:` | `['- doSomething:']` |
| `- (id)initWithFrame:style:` | `['- initWithFrame:style:']` |
| `+ (id)sharedInstance` | `['+ sharedInstance']` |

When calling ObjC methods from Frida JS, colons become underscores in the method name:

```javascript
// ObjC: [obj initWithFrame:frame style:style]
// Frida: obj.initWithFrame_style_(frame, style)
```

## Class Enumeration

### List All Loaded Classes

```javascript
// All classes (can be thousands)
const classes = ObjC.enumerateLoadedClassesSync();
for (const [module, classNames] of Object.entries(classes)) {
  classNames.forEach(name => console.log(`${module}: ${name}`));
}

// Filter by prefix
ObjC.enumerateLoadedClassesSync({
  ownedBy: Process.findModuleByName('MyApp')
});
```

### List Methods on a Class

```javascript
const cls = ObjC.classes.NSURLSession;

// Instance methods
cls.$ownMethods
  .filter(m => m.startsWith('- '))
  .forEach(m => console.log(m));

// Class methods
cls.$ownMethods
  .filter(m => m.startsWith('+ '))
  .forEach(m => console.log(m));

// All methods including inherited
cls.$methods.forEach(m => console.log(m));
```

### Check If a Class Exists

```javascript
if (ObjC.classes.hasOwnProperty('SomeClass')) {
  // Safe to use ObjC.classes.SomeClass
}
```

## Hooking ObjC Methods

### Instance Method Hook

```javascript
Interceptor.attach(
  ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation,
  {
    onEnter(args) {
      const request = new ObjC.Object(args[2]);
      console.log(`URL: ${request.URL().absoluteString()}`);
      console.log(`Method: ${request.HTTPMethod()}`);

      const body = request.HTTPBody();
      if (body !== null) {
        console.log(`Body: ${body.bytes().readUtf8String(body.length())}`);
      }
    }
  }
);
```

### Class Method Hook

```javascript
Interceptor.attach(
  ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation,
  {
    onEnter(args) {
      const obj = new ObjC.Object(args[2]);
      console.log(`Serializing: ${obj.toString()}`);
    }
  }
);
```

### Using ApiResolver for Wildcard Matching

```javascript
const resolver = new ApiResolver('objc');

// All methods matching a pattern
resolver.enumerateMatches('-[NSURL* *HTTP*]').forEach(match => {
  console.log(`${match.name} @ ${match.address}`);
});

// Hook all matches
resolver.enumerateMatches('-[*ViewController viewDidLoad]').forEach(match => {
  Interceptor.attach(match.address, {
    onEnter() {
      console.log(`viewDidLoad: ${match.name}`);
    }
  });
});
```

## Working with ObjC Objects

### Reading Properties

```javascript
const obj = new ObjC.Object(ptr_value);

// Call getter methods
const name = obj.name();                    // Returns ObjC.Object
const nameStr = obj.name().toString();      // Convert to JS string
const count = obj.count().valueOf();        // Convert to JS number
```

### NSData Handling

```javascript
function nsDataToString(nsData) {
  if (nsData === null) return null;
  const data = new ObjC.Object(nsData);
  return data.bytes().readUtf8String(data.length());
}

function nsDataToHex(nsData) {
  const data = new ObjC.Object(nsData);
  const bytes = data.bytes().readByteArray(data.length());
  return Array.from(new Uint8Array(bytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
}
```

### NSArray and NSDictionary

```javascript
function nsArrayToJS(nsArray) {
  const arr = new ObjC.Object(nsArray);
  const result = [];
  for (let i = 0; i < arr.count().valueOf(); i++) {
    result.push(arr.objectAtIndex_(i).toString());
  }
  return result;
}

function nsDictToJS(nsDict) {
  const dict = new ObjC.Object(nsDict);
  const keys = dict.allKeys();
  const result = {};
  for (let i = 0; i < keys.count().valueOf(); i++) {
    const key = keys.objectAtIndex_(i);
    result[key.toString()] = dict.objectForKey_(key).toString();
  }
  return result;
}
```

## ObjC.choose: Heap Scanning

Find live objects of a specific class on the heap:

```javascript
ObjC.choose(ObjC.classes.UIViewController, {
  onMatch(instance) {
    console.log(`Found VC: ${instance.$className} @ ${instance.handle}`);
    // Return 'stop' to end early
  },
  onComplete() {
    console.log('Heap scan complete');
  }
});
```

**Performance warning**: `ObjC.choose()` scans the entire heap. Only use for:
- Finding singleton instances
- Inspecting live object state
- Debugging specific object graphs

Do NOT use in loops or hot paths.

## Swift Hooking

### Swift Methods That Bridge to ObjC

Most UIKit/Foundation-based Swift methods are accessible through the ObjC runtime:

```javascript
// Swift class inheriting from NSObject
// class MyViewController: UIViewController { ... }
// These are visible in ObjC.classes:
ObjC.classes.MyApp_MyViewController['- viewDidLoad'].implementation;
```

The class name is typically `ModuleName.ClassName` or `ModuleName_ClassName` in the ObjC runtime.

### Pure Swift Methods

Pure Swift methods (not bridged to ObjC) require symbol resolution:

```javascript
// Find the mangled symbol
Module.enumerateExports('MyApp').forEach(e => {
  if (e.name.includes('calculateTotal'))  // Search for partial name
    console.log(`${e.name} @ ${e.address}`);
});

// Demangle Swift symbols for readability
// Swift symbols start with $s or _$s
Module.enumerateExports('MyApp').forEach(e => {
  if (e.name.startsWith('$s') || e.name.startsWith('_$s'))
    console.log(`${e.name} @ ${e.address}`);
});

// Hook by address
Interceptor.attach(ptr('0x100012345'), {
  onEnter(args) {
    // Pure Swift args follow platform calling convention
    // Not ObjC dispatch — no self/cmd at args[0]/args[1]
    console.log('Swift function called');
  }
});
```

### Swift String Handling

Swift Strings are not NSStrings internally (they use a tagged pointer representation):

```javascript
// If the Swift method returns an NSString-bridged type:
const result = new ObjC.Object(retval);
console.log(result.toString());

// If it returns a pure Swift.String:
// You'll need to read the raw struct layout
// Swift.String is 16 bytes on 64-bit: pointer + length/flags
```

## Blocks (Closures)

ObjC blocks are common callback parameters:

```javascript
// Reading a block's implementation
const block = new ObjC.Block(args[3]);
console.log(`Block implementation: ${block.implementation}`);

// Replacing a block's implementation
const originalImpl = block.implementation;
block.implementation = function(arg1, arg2) {
  console.log(`Block called with: ${arg1}, ${arg2}`);
  return originalImpl(arg1, arg2);
};
```

## Thread Safety with ObjC

### Main Thread Access

UI-related operations must run on the main thread:

```javascript
ObjC.schedule(ObjC.mainQueue, function() {
  // Safe to access UI objects here
  const app = ObjC.classes.UIApplication.sharedApplication();
  const window = app.keyWindow();
  console.log(`Window: ${window}`);
});
```

### Autorelease Pool

Long-running scripts that create many ObjC objects should use autorelease pools:

```javascript
const pool = ObjC.classes.NSAutoreleasePool.alloc().init();
try {
  // Create and use ObjC objects
} finally {
  pool.release();
}
```
