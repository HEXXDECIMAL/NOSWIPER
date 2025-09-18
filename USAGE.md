# NoSwiper Usage Examples

## Quick Start

### 1. Build and Test

```bash
# Build the project
cargo build --release

# Check the help
./target/release/noswiper-daemon --help

# View the default configuration
./target/release/noswiper-daemon --show-config
```

### 2. Test Interactive Mode (Recommended for First Use)

```bash
# Start the daemon in interactive mode (requires sudo)
sudo ./target/release/noswiper-daemon --interactive
```

You should see:
```
NoSwiper running in interactive mode
Access prompts will appear in this terminal
Press Ctrl+C to exit

[INFO] NoSwiper daemon starting
[INFO] Version: 0.1.0
[INFO] Mode: interactive
[INFO] Mechanism: auto
[INFO] Auto-selecting eslogger for macOS
[INFO] Using eslogger mechanism
[INFO] Started eslogger process
```

### 3. Test Credential Access Detection

In another terminal, try accessing a protected file:

```bash
# Try to read SSH private key (will be detected)
cat ~/.ssh/id_rsa

# Or with a different tool
/bin/cat ~/.ssh/id_rsa

# Try accessing AWS credentials
cat ~/.aws/credentials
```

### 4. See the Interactive Prompt

When you access a protected file, you'll see a prompt like this:

```
============================================================
⚠️  CREDENTIAL ACCESS DETECTED
============================================================
Application: cat
Full path:   /bin/cat
Credential:  /Users/yourname/.ssh/id_rsa

This application is trying to access sensitive credentials.

Options:
  [A]llow once
  [D]eny (default)
  [W]hitelist this app for this credential
  [S]how more info

Decision [A/d/w/s]?
```

### 5. Test Different Options

- **[A]llow once**: Allows this specific access and logs it
- **[D]eny**: Denies access (default if you just press Enter)
- **[W]hitelist**: Permanently allows this app to access this credential
- **[S]how more info**: Shows additional information about the process

### 6. Test Legitimate Access

```bash
# SSH should be allowed to access SSH keys
ssh -T git@github.com

# Git should be allowed to access SSH keys
git fetch
```

You should see log messages like:
```
[INFO] ALLOWED: /usr/bin/ssh -> /Users/yourname/.ssh/id_rsa
```

## Production Usage

### Monitor Mode (Logging Only)

```bash
# Just log access attempts, don't block anything
sudo ./target/release/noswiper-daemon --monitor
```

### Enforce Mode (Block Unauthorized Access)

```bash
# Block unauthorized access attempts
sudo ./target/release/noswiper-daemon --enforce
```

**Note**: On macOS with eslogger, this currently only logs violations. For real blocking, ESF support is needed (future version).

## Log Output Examples

### Allowed Access
```
[INFO] ALLOWED: /usr/bin/ssh -> /Users/alice/.ssh/id_rsa
[INFO] ALLOWED: /usr/bin/git -> /Users/alice/.ssh/id_rsa
```

### Blocked Access
```
[WARN] DETECTED: /bin/cat -> /Users/alice/.ssh/id_rsa
[ERROR] BLOCKED: /tmp/malware -> /Users/alice/.ssh/id_rsa
```

### Interactive Decisions
```
[INFO] User allowed access: cat -> /Users/alice/.ssh/id_rsa
[INFO] User whitelisted: backup-tool -> /Users/alice/.ssh/id_rsa
[WARN] User denied access: suspicious-app -> /Users/alice/.ssh/id_rsa
```

## Testing Specific Scenarios

### Test SSH Key Protection

```bash
# These should be ALLOWED (if tools are in legitimate locations)
ssh-add -l
git status
rsync -av ~/.ssh/id_rsa.pub user@server:

# These should be DETECTED/BLOCKED
cat ~/.ssh/id_rsa
cp ~/.ssh/id_rsa /tmp/
/tmp/malware ~/.ssh/id_rsa
```

### Test AWS Credentials

```bash
# These should be ALLOWED
aws s3 ls
terraform plan

# These should be DETECTED/BLOCKED
cat ~/.aws/credentials
cp ~/.aws/credentials /tmp/
```

### Test Browser Credentials

```bash
# These should be DETECTED/BLOCKED
cat "~/Library/Application Support/Google/Chrome/Default/Login Data"
cp "~/Library/Application Support/Firefox/Profiles/*/logins.json" /tmp/
```

## Expected Behavior

### What Gets Protected
- SSH private keys (`~/.ssh/id_*`, `~/.ssh/*_key`)
- Cloud provider credentials (AWS, GCP, Azure)
- Package manager tokens (npm, pip, cargo, etc.)
- Browser password databases
- GPG private keys
- Password manager databases

### What Doesn't Get Protected
- SSH public keys (`~/.ssh/*.pub`)
- SSH config files (`~/.ssh/config`)
- Public GPG keys
- Any files not matching protection patterns

### Which Programs Are Allowed
Each credential type has specific allowed programs:
- **SSH keys**: ssh, git, rsync, scp, ssh-add, ssh-agent
- **AWS credentials**: aws, terraform, ansible, packer
- **NPM tokens**: npm, yarn, node, pnpm
- etc.

### Process Verification
Programs are verified to be in legitimate locations:
- `/usr/bin/*`, `/bin/*` (system binaries)
- `/opt/homebrew/bin/*` (Homebrew on Apple Silicon)
- `/usr/local/bin/*` (Homebrew on Intel, manual installs)
- `/Applications/*.app/Contents/MacOS/*` (macOS applications)

On macOS, code signatures are also verified when available.

## Troubleshooting

### "eslogger not found"
```bash
# Check if eslogger is available
which eslogger

# On newer macOS versions, it should be available by default
# If not, you may need to install Xcode Command Line Tools
xcode-select --install
```

### No Events Detected
- Make sure you're running as root: `sudo ./target/release/noswiper-daemon`
- Check that you have protected files: `ls ~/.ssh/id_*`
- Try creating a test SSH key: `ssh-keygen -t rsa -f ~/.ssh/test_key`

### Permission Denied
- Ensure you're running with `sudo`
- On macOS, you may need to grant Full Disk Access to Terminal in System Preferences

### Logs Not Appearing
- Check log level: add `--log-level debug` for verbose output
- Make sure eslogger is working: `sudo eslogger file --format json` (should show file access events)

## Next Steps

1. **Install systemwide**: Copy binary to `/usr/local/bin/noswiper-daemon`
2. **Create service**: Set up systemd (Linux) or launchd (macOS) service
3. **Configure logging**: Set up log rotation and monitoring
4. **Test thoroughly**: Run in monitor mode for a while before enabling enforce mode