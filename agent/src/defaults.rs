// This file is deprecated - all rules are now in config/default.yaml
// Keeping minimal structure for backward compatibility during transition

/// Default protected credential patterns and their allowed programs
/// DEPRECATED: Use config/default.yaml instead
#[allow(dead_code)]
pub const DEFAULT_PROTECTED: &[(&str, &[&str])] = &[
    // SSH Keys
    (
        "~/.ssh/id_*",
        &["ssh", "ssh-add", "ssh-agent", "git", "rsync", "scp"],
    ),
    (
        "~/.ssh/*_key",
        &["ssh", "ssh-add", "ssh-agent", "git", "rsync", "scp"],
    ),
    // AWS Credentials
    (
        "~/.aws/credentials",
        &["aws", "terraform", "ansible", "packer", "boto3"],
    ),
    ("~/.aws/config", &["aws", "terraform", "ansible", "packer"]),
    // Google Cloud Platform
    (
        "~/.config/gcloud/**/credentials.db",
        &["gcloud", "gsutil", "terraform", "kubectl"],
    ),
    (
        "~/.config/gcloud/**/access_tokens.db",
        &["gcloud", "gsutil", "terraform"],
    ),
    ("~/.config/gcloud/**/adc.json", &["gcloud", "terraform"]),
    // Azure
    (
        "~/.azure/accessTokens.json",
        &["az", "azure-cli", "terraform"],
    ),
    (
        "~/.azure/azureProfile.json",
        &["az", "azure-cli", "terraform"],
    ),
    // Kubernetes
    (
        "~/.kube/config",
        &["kubectl", "helm", "k9s", "terraform", "lens"],
    ),
    ("~/.kube/*/config", &["kubectl", "helm", "k9s", "terraform"]),
    // GPG Keys
    ("~/.gnupg/secring.gpg", &["gpg", "gpg2", "git", "pass"]),
    (
        "~/.gnupg/private-keys-*.d/*",
        &["gpg", "gpg2", "git", "pass"],
    ),
    // Package Manager Credentials
    ("~/.npmrc", &["npm", "yarn", "pnpm", "node"]),
    ("~/.pypirc", &["pip", "pip3", "poetry", "pipenv", "twine"]),
    ("~/.cargo/credentials*", &["cargo", "rustup"]),
    ("~/.docker/config.json", &["docker", "podman", "containerd"]),
    ("~/.gem/credentials", &["gem", "bundle", "bundler"]),
    ("~/.m2/settings.xml", &["mvn", "maven", "gradle"]),
    ("~/.m2/settings-security.xml", &["mvn", "maven", "gradle"]),
    // Browser Profiles (macOS paths)
    (
        "~/Library/Application Support/Firefox/Profiles/*/logins.json",
        &["firefox", "Firefox"],
    ),
    (
        "~/Library/Application Support/Firefox/Profiles/*/key*.db",
        &["firefox", "Firefox"],
    ),
    (
        "~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite",
        &["firefox", "Firefox"],
    ),
    (
        "~/Library/Application Support/Google/Chrome/*/Login Data",
        &["chrome", "Google Chrome"],
    ),
    (
        "~/Library/Application Support/Google/Chrome/*/Cookies",
        &["chrome", "Google Chrome"],
    ),
    (
        "~/Library/Application Support/Google/Chrome/*/Web Data",
        &["chrome", "Google Chrome"],
    ),
    (
        "~/Library/Application Support/Chromium/*/Login Data",
        &["chromium"],
    ),
    (
        "~/Library/Application Support/Chromium/*/Cookies",
        &["chromium"],
    ),
    (
        "~/Library/Safari/Bookmarks.plist",
        &["Safari", "SafariServices"],
    ),
    (
        "~/Library/Cookies/Cookies.binarycookies",
        &["Safari", "SafariServices"],
    ),
    // Browser Profiles (Linux paths)
    (
        "~/.mozilla/firefox/*/logins.json",
        &["firefox", "firefox-bin"],
    ),
    ("~/.mozilla/firefox/*/key*.db", &["firefox", "firefox-bin"]),
    (
        "~/.mozilla/firefox/*/cookies.sqlite",
        &["firefox", "firefox-bin"],
    ),
    (
        "~/.config/google-chrome/*/Login Data",
        &["chrome", "google-chrome", "google-chrome-stable"],
    ),
    (
        "~/.config/google-chrome/*/Cookies",
        &["chrome", "google-chrome", "google-chrome-stable"],
    ),
    (
        "~/.config/google-chrome/*/Web Data",
        &["chrome", "google-chrome", "google-chrome-stable"],
    ),
    (
        "~/.config/chromium/*/Login Data",
        &["chromium", "chromium-browser"],
    ),
    (
        "~/.config/chromium/*/Cookies",
        &["chromium", "chromium-browser"],
    ),
    // Password Managers
    (
        "~/.password-store/**/*.gpg",
        &["pass", "gpg", "gpg2", "passmenu"],
    ),
    (
        "~/.local/share/keyrings/*.keyring",
        &["gnome-keyring-daemon", "seahorse", "secret-tool"],
    ),
    (
        "~/Library/Keychains/login.keychain-db",
        &[
            "security",
            "Keychain Access",
            "SecurityAgent",
            "codesign",
            "accountsd",     // Apple account management
            "sharingd",      // Apple sharing services
            "cloudd",        // iCloud services
            "Safari",        // Safari browser
            "Google Chrome", // Google Chrome browser
            "Google Drive",  // Google Drive sync
            "Dropbox",       // Dropbox sync
            "1Password",     // Password managers
            "Bitwarden",
            "LastPass",
            "Dashlane",
            "securityd", // macOS security daemon
            "trustd",    // Certificate trust daemon
        ],
    ),
    (
        "~/Library/Keychains/*.keychain-db",
        &[
            "security",
            "Keychain Access",
            "SecurityAgent",
            "codesign",
            "accountsd",     // Apple account management
            "sharingd",      // Apple sharing services
            "cloudd",        // iCloud services
            "Safari",        // Safari browser
            "Google Chrome", // Google Chrome browser
            "Google Drive",  // Google Drive sync
            "Dropbox",       // Dropbox sync
            "1Password",     // Password managers
            "Bitwarden",
            "LastPass",
            "Dashlane",
            "securityd", // macOS security daemon
            "trustd",    // Certificate trust daemon
        ],
    ),
    (
        "~/Library/Keychains/*/keychain-2.db",
        &[
            "security",
            "Keychain Access",
            "SecurityAgent",
            "codesign",
            "accountsd",
            "sharingd",
            "cloudd",
            "securityd",
            "trustd",
        ],
    ),
    (
        "~/Documents/*.kdbx",
        &["keepassxc", "keepassx", "keepass2", "kpcli"],
    ),
    ("~/*.kdbx", &["keepassxc", "keepassx", "keepass2", "kpcli"]),
    ("~/.config/Bitwarden/data.json", &["bitwarden", "Bitwarden"]),
    (
        "~/Library/Application Support/Bitwarden/data.json",
        &["bitwarden", "Bitwarden"],
    ),
];

/// Patterns that should never be protected (public keys, configs, etc.)
#[allow(dead_code)]
pub const EXCLUDED_PATTERNS: &[&str] = &[
    "~/.ssh/*.pub",
    "~/.ssh/known_hosts",
    "~/.ssh/config",
    "~/.gnupg/pubring.gpg",
    "~/.gnupg/trustdb.gpg",
];

/// Common paths for legitimate programs on macOS
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub const MACOS_COMMON_PATHS: &[&str] = &[
    // System binaries
    "/usr/bin/*",
    "/bin/*",
    "/usr/local/bin/*",
    "/usr/sbin/*",
    "/sbin/*",
    // Homebrew
    "/opt/homebrew/bin/*",
    "/opt/homebrew/sbin/*",
    // MacPorts
    "/opt/local/bin/*",
    "/opt/local/sbin/*",
    // User installations
    "/Users/*/.cargo/bin/*",
    "/Users/*/.local/bin/*",
    "/Users/*/go/bin/*",
    "/Users/*/.rbenv/shims/*",
    // Development tools
    "/Applications/Xcode.app/Contents/Developer/usr/bin/*",
    "/Library/Developer/CommandLineTools/usr/bin/*",
    // Applications
    "/Applications/*.app/Contents/MacOS/*",
];

/// Common paths for legitimate programs on Linux
#[allow(dead_code)] // Will be removed after full migration
pub const LINUX_COMMON_PATHS: &[&str] = &[
    // System binaries
    "/usr/bin/*",
    "/bin/*",
    "/usr/local/bin/*",
    "/usr/sbin/*",
    "/sbin/*",
    // User installations
    "/home/*/.cargo/bin/*",
    "/home/*/.local/bin/*",
    "/home/*/go/bin/*",
    "/home/*/.rbenv/shims/*",
    // Common package manager locations
    "/usr/lib/*/bin/*",
    "/opt/*/bin/*",
];

// Functions deprecated - use Config methods instead
