#!/usr/bin/env python3
"""Create icon files for Tauri app"""

from PIL import Image, ImageDraw, ImageFont
import os

# Create icons directory
os.makedirs("icons", exist_ok=True)

# Create a simple icon with a shield and lock
def create_icon(size):
    # Create a new image with a gradient background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw a shield shape
    padding = size // 8
    shield_points = [
        (size // 2, padding),  # Top center
        (size - padding, size // 3),  # Top right
        (size - padding, size * 2 // 3),  # Right side
        (size // 2, size - padding),  # Bottom center
        (padding, size * 2 // 3),  # Left side
        (padding, size // 3),  # Top left
        (size // 2, padding),  # Back to top
    ]

    # Draw shield with gradient effect
    draw.polygon(shield_points, fill=(102, 126, 234, 255), outline=(76, 75, 162, 255), width=2)

    # Draw a lock symbol in the center
    lock_size = size // 3
    lock_x = (size - lock_size) // 2
    lock_y = (size - lock_size) // 2 + size // 10

    # Lock body
    draw.rectangle(
        [lock_x, lock_y + lock_size // 3, lock_x + lock_size, lock_y + lock_size],
        fill=(255, 255, 255, 200),
        outline=(50, 50, 50, 255),
        width=1
    )

    # Lock shackle
    shackle_width = lock_size // 5
    draw.arc(
        [lock_x + shackle_width, lock_y, lock_x + lock_size - shackle_width, lock_y + lock_size // 2],
        start=180, end=0,
        fill=(255, 255, 255, 200),
        width=3
    )

    # Keyhole
    keyhole_x = lock_x + lock_size // 2
    keyhole_y = lock_y + lock_size * 2 // 3
    keyhole_r = lock_size // 10
    draw.ellipse(
        [keyhole_x - keyhole_r, keyhole_y - keyhole_r,
         keyhole_x + keyhole_r, keyhole_y + keyhole_r],
        fill=(50, 50, 50, 255)
    )

    return img

# Generate icons of different sizes
sizes = {
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "icon.png": 512,
}

for filename, size in sizes.items():
    img = create_icon(size)
    img.save(f"icons/{filename}")
    print(f"Created icons/{filename}")

# Create .ico file for Windows (multiple sizes)
img_32 = create_icon(32)
img_16 = create_icon(16)
img_48 = create_icon(48)
img_256 = create_icon(256)
img_256.save("icons/icon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
print("Created icons/icon.ico")

# Create .icns file for macOS (this is complex, so we'll just copy the largest PNG)
# In production, you'd use a proper tool like iconutil
import shutil
shutil.copy("icons/icon.png", "icons/icon.icns")
print("Created icons/icon.icns (placeholder)")

print("All icons created successfully!")
