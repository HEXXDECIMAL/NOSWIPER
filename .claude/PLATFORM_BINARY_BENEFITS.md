# Platform Binary Field Benefits

## Before (without platform_binary)

```yaml
# Had to list many Apple system processes individually:
global_exclusions:
  - base: "securityd"
    app_id: "com.apple.*"
    path_pattern: "/System/*"
  - base: "accountsd"
    app_id: "com.apple.*"
    path_pattern: "/System/*"
  - base: "cloudd"
    app_id: "com.apple.*"
    path_pattern: "/System/*"
  - base: "sharingd"
    app_id: "com.apple.*"
    path_pattern: "/System/*"
  # ... and dozens more
```

Problems:
1. **Incomplete** - Easy to miss Apple system processes
2. **Maintenance burden** - New system processes in OS updates need manual addition
3. **Verbose** - Lots of repetition
4. **Error-prone** - Can accidentally include non-Apple processes with similar names

## After (with platform_binary)

```yaml
# Simple, comprehensive coverage:
global_exclusions:
  # Allow all Apple platform binaries
  - platform_binary: true
    path_pattern: "/System/*"
  - platform_binary: true
    path_pattern: "/usr/bin/*"
  - platform_binary: true
    path_pattern: "/usr/libexec/*"
```

Benefits:
1. **Complete** - Automatically covers ALL Apple platform binaries
2. **Future-proof** - New system processes in OS updates automatically covered
3. **Concise** - Much cleaner configuration
4. **Secure** - Uses cryptographically signed `is_platform_binary` flag from macOS

## Security Advantages

The `platform_binary` field uses the `is_platform_binary` flag from macOS's Endpoint Security Framework, which:

1. **Cannot be spoofed** - It's determined by the OS based on code signatures
2. **Verified by Apple** - Only binaries signed with Apple's platform keys get this flag
3. **More reliable than team_id** - Some Apple binaries have `team_id: null` but `is_platform_binary: true`

## Examples of Proper Classification

| Binary | team_id | is_platform_binary | Display |
|--------|---------|-------------------|---------|
| /usr/bin/security | null | true | `<Apple>` |
| /usr/libexec/sharingd | null | true | `<Apple>` |
| /System/Library/PrivateFrameworks/*/XPCService | null | true | `<Apple>` |
| /Applications/Review Goose.app | null | false | `<Self>` |
| /Applications/1Password.app | 2BUA8C4S2C | false | `<2BUA8C4S2C>` |

## Migration Guide

To update existing configurations:

1. **Identify Apple system processes** in your current rules
2. **Replace with platform_binary rules** for cleaner config
3. **Test thoroughly** to ensure expected behavior
4. **Benefit from automatic coverage** of all platform binaries

## Use Cases

### Allow all Apple system processes to access keychains
```yaml
global_exclusions:
  - platform_binary: true  # Simple!
```

### Allow only non-platform binaries for developer credentials
```yaml
allow_rules:
  - base: "aws"
    platform_binary: false  # Explicitly require non-platform
```

### Mixed rules for specific scenarios
```yaml
allow_rules:
  - base: "security"
    platform_binary: true   # Apple's security tool
  - base: "1Password*"
    platform_binary: false  # Third-party password manager
    team_id: "2BUA8C4S2C"
```