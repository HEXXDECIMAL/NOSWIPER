#!/bin/bash
# Build script for NoSwiper native macOS UI
# This script uses swiftc instead of xcodebuild to avoid requiring Xcode

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_DIR="build"
CONFIGURATION="${1:-Debug}"
APP_NAME="NoSwiper"
BUNDLE_ID="com.noswiper.app"

echo "Building NoSwiper macOS UI ($CONFIGURATION)..."

# Clean build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Create app bundle structure
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
CONTENTS="$APP_BUNDLE/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

mkdir -p "$MACOS"
mkdir -p "$RESOURCES"

# Compile Swift sources
echo "Compiling Swift sources..."
SWIFT_FILES=(
    "NoSwiper/NoSwiperApp.swift"
    "NoSwiper/ContentView.swift"
    "NoSwiper/IPCClient.swift"
    "NoSwiper/ViolationAlert.swift"
    "NoSwiper/MenuBarController.swift"
    "NoSwiper/OverrideRulesWindow.swift"
    "NoSwiper/ViolationHistoryWindow.swift"
)

# Determine optimization flags
if [ "$CONFIGURATION" = "Release" ]; then
    OPTIMIZATION="-O"
else
    OPTIMIZATION="-Onone -g"
fi

swiftc \
    "${SWIFT_FILES[@]}" \
    -o "$MACOS/$APP_NAME" \
    -module-name NoSwiper \
    $OPTIMIZATION \
    -sdk $(xcrun --show-sdk-path) \
    -target arm64-apple-macosx13.0 \
    -import-objc-header NoSwiper/NoSwiper-Bridging-Header.h 2>/dev/null || \
swiftc \
    "${SWIFT_FILES[@]}" \
    -o "$MACOS/$APP_NAME" \
    -module-name NoSwiper \
    $OPTIMIZATION \
    -sdk $(xcrun --show-sdk-path) \
    -target arm64-apple-macosx13.0

# Copy Assets
echo "Copying assets..."
if [ -d "NoSwiper/Assets.xcassets" ]; then
    cp -r "NoSwiper/Assets.xcassets" "$RESOURCES/"
fi

# Create Info.plist
echo "Creating Info.plist..."
cat > "$CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Create PkgInfo
echo "APPL????" > "$CONTENTS/PkgInfo"

echo "✓ Build complete: $APP_BUNDLE"
echo ""
echo "To run: open $APP_BUNDLE"
