# Move Entry Point Detection (Aptos)

## Entry Point Identification (State-Changing Only)

Include state-changing `public fun`, `public entry fun`, and `entry fun` functions.
Aptos transaction scripts can call public functions without the `entry` modifier.
Inspect bodies and callees for state effects rather than assuming visibility
implies mutation. Private non-entry, `public(package)`, and `public(friend)`
functions are not independent transaction entry points; trace them when reachable
from an included function.

### Aptos Move
```move
// Public entry functions are entry points
public entry fun transfer(from: &signer, to: address, amount: u64) { }

// Public functions callable by modules and transaction scripts
public fun read_value(): u64 { 0 } // Read-only body: exclude from this inventory

// Entry-only functions (can't be called by other modules)
entry fun private_entry(account: &signer) { }
```

### Visibility Rules
| Visibility | Include? | Notes |
|------------|----------|-------|
| `public entry fun` | **Yes** | Transaction entry point (state-changing) |
| `entry fun` | **Yes** | Transaction-only entry point |
| `public fun` | **Yes**, if state-changing | Callable through transaction scripts or other modules |
| `fun` (private) | No | Not externally callable |
| `public(friend) fun` | No | Friend modules only |

## Access Control Patterns

### Signer-Based Control (Aptos)
```move
// Admin check via signer
public entry fun admin_action(admin: &signer) {
    assert!(signer::address_of(admin) == @admin_address, E_NOT_ADMIN);
}

// Owner check via resource
public entry fun owner_action(owner: &signer) acquires Config {
    let config = borrow_global<Config>(@module_addr);
    assert!(signer::address_of(owner) == config.owner, E_NOT_OWNER);
}
```

### Capability Pattern (Aptos)
```move
// Capability resource
struct AdminCap has key, store {}

// Requires capability
public entry fun admin_action(admin: &signer) acquires AdminCap {
    assert!(exists<AdminCap>(signer::address_of(admin)), E_NO_CAP);
}
```

### Access Control Classification
| Pattern | Classification |
|---------|----------------|
| `signer::address_of(s) == @admin` | Admin |
| `signer::address_of(s) == config.owner` | Owner |
| `exists<AdminCap>(addr)` | Admin (capability) |
| `exists<GovernanceCap>(addr)` | Governance |
| `exists<GuardianCap>(addr)` | Guardian |
| `&signer` with no role checks | Public; record which signer's resources it can access |

## Contract-Only Detection

### Friend Functions
```move
// Only callable by friend modules
public(friend) fun internal_callback() { }

// Friend declaration
friend other_module;
```

### Module-to-Module Patterns
```move
// Functions designed for other modules
public fun on_transfer_hook(amount: u64): bool {
    // Intended for token modules, but public visibility also permits scripts
}
```

## Extraction Strategy

### Aptos
1. Parse all `.move` files
2. Find `module` declarations
3. Extract `public fun`, `public entry fun`, and `entry fun`; exclude read-only bodies
4. Check function body for:
   - `signer::address_of` comparisons → Role-based
   - `exists<*Cap>` checks → Capability-based
   - No caller-role checks → Public (Unrestricted); a signer argument alone is not an admin check
5. Record capability and signer requirements, including whether callers can obtain the required values

## Move-Specific Considerations

1. **Resource Model**: Access control often through resource ownership
2. **Capabilities**: `Cap` suffix typically indicates capability pattern
3. **Acquires**: `acquires Resource` shows what global resources are accessed
4. **Generic Types**: Type parameters may carry capability constraints
5. **Friend Visibility**: `public(friend)` limits callers to declared friends

## Common Gotchas

1. **Init Functions**: `init` or `initialize` often create initial capabilities
2. **Module Upgrades**: Check upgrade capability ownership
3. **Phantom Types**: Type parameters with `phantom` don't affect runtime
