# Missing Secrets Commonly Targeted by Infostealers

## Cryptocurrency Wallets
These are extremely high-value targets for infostealers:

### Desktop Wallets
- **Electrum**: `~/.electrum/wallets/`
- **Bitcoin Core**: `~/.bitcoin/wallet.dat`
- **Ethereum**: `~/.ethereum/keystore/`
- **Exodus**: `~/Library/Application Support/Exodus/` (macOS), `~/.config/Exodus/` (Linux)
- **Atomic Wallet**: `~/Library/Application Support/atomic/` (macOS), `~/.config/atomic/` (Linux)
- **Jaxx**: `~/Library/Application Support/Jaxx/` (macOS)
- **MetaMask** (browser extension data - already partially covered in browser stores)
- **Monero**: `~/.bitmonero/`, `~/Monero/wallets/`
- **Ledger Live**: `~/Library/Application Support/Ledger Live/` (macOS), `~/.config/Ledger Live/` (Linux)

## Gaming Platform Credentials
- **Steam**: `~/Library/Application Support/Steam/config/loginusers.vdf` (macOS), `~/.steam/steam/config/loginusers.vdf` (Linux)
- **Epic Games**: Auth tokens in browser storage (partially covered)
- **Discord**: `~/Library/Application Support/discord/Local Storage/leveldb/` (macOS), `~/.config/discord/Local Storage/leveldb/` (Linux)

## VPN Configurations
Often contain credentials or certificates:
- **OpenVPN**: `~/Library/Application Support/OpenVPN Connect/profiles/` (macOS), `~/.config/openvpn/` (Linux)
- **WireGuard**: `/etc/wireguard/*.conf`, `~/.config/wireguard/`
- **NordVPN**: `~/Library/Preferences/com.nordvpn.NordVPN.plist` (macOS)
- **ExpressVPN**: Various config files

## Development Tokens & API Keys
- **GitHub Copilot**: `~/.config/github-copilot/`
- **Netlify**: `~/.netlify/`
- **Vercel**: `~/.vercel/`
- **Heroku**: `~/.netrc` (contains Heroku API tokens)
- **DigitalOcean**: `~/.config/doctl/`
- **Fly.io**: `~/.fly/`

## Database Clients
- **TablePlus**: `~/Library/Application Support/com.tinyapp.TablePlus/` (macOS)
- **Sequel Pro**: `~/Library/Application Support/Sequel Pro/` (macOS)
- **DBeaver**: `~/.dbeaver/` workspace contains connection configs
- **MongoDB Compass**: Connection strings in app data
- **pgAdmin**: `~/.pgadmin/`
- **MySQL Workbench**: `~/.mysql/workbench/`

## Communication Apps
- **Slack**: `~/Library/Application Support/Slack/` (macOS), `~/.config/Slack/` (Linux)
- **Signal**: `~/Library/Application Support/Signal/` (macOS), `~/.config/Signal/` (Linux)
- **Telegram**: `~/Library/Application Support/Telegram Desktop/` (macOS), `~/.local/share/TelegramDesktop/` (Linux)
- **Element (Matrix)**: `~/.config/Element/`

## File Sharing & FTP
- **FileZilla**: `~/.config/filezilla/sitemanager.xml`, `~/.filezilla/`
- **Cyberduck**: `~/Library/Group Containers/G69SCX94XU.duck/Library/Application Support/duck/Bookmarks/` (macOS)
- **Transmit**: `~/Library/Application Support/Transmit/` (macOS)
- **WinSCP** (Windows, but worth noting): stored sessions

## Session Files & Cookies
- **Generic session files**: `~/.config/*/session*`, `~/.local/share/*/session*`
- **Cookies from Electron apps**: Many Electron apps store cookies in predictable locations

## Environment Files
- **Shell history with secrets**:
  - `~/.bash_history` - often contains passwords typed in commands
  - `~/.zsh_history`
  - `~/.fish_history`
- **Environment variables**: `~/.env`, `~/.envrc`

## Mail Clients (Additional)
- **Outlook**: Various PST/OST file locations
- **Airmail**: `~/Library/Containers/it.bloop.airmail*/` (macOS)
- **Spark**: `~/Library/Containers/com.readdle.smartemail-Mac/` (macOS)

## IDE/Editor Configurations
- **JetBrains IDEs**: `~/.config/JetBrains/*/options/security.xml`
- **VS Code Settings Sync**: Contains GitHub tokens
- **Sublime Text**: Package control may have API keys

## macOS Specific
- **Safari Bookmarks**: `~/Library/Safari/Bookmarks.plist` (can reveal internal URLs)
- **macOS Mail rules**: `~/Library/Mail/V*/MailData/SyncedRules.plist`
- **Network Passwords**: Already covered via Keychain
- **iCloud Keychain**: Covered via login keychain

## Linux Specific
- **NetworkManager**: `/etc/NetworkManager/system-connections/*` (WiFi passwords)
- **GNOME Keyring**: `~/.local/share/keyrings/`
- **KWallet**: `~/.local/share/kwalletd/`

## Notes & Documentation Apps
Often contain passwords/secrets:
- **Obsidian**: `~/Documents/Obsidian Vault/` or custom locations
- **Notion**: Local cache files
- **Bear**: `~/Library/Group Containers/9K33E3U3T4.net.shinyfrog.bear/` (macOS)
- **Apple Notes**: Already covered via macOS system

## Recommendations:
1. **Priority additions**: Cryptocurrency wallets, Discord, Steam, FileZilla
2. **Consider rate limiting**: Some of these are accessed frequently by legitimate apps
3. **User education**: Many of these contain data users don't realize is sensitive