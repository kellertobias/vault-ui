import os
import glob
from PIL import Image, ImageDraw

def create_app_icon(size, lock_img):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw blue squircle
    radius = int(size * 0.225)
    blue_color = (23, 93, 220, 255) # Bitwarden blue #175DDC
    draw.rounded_rectangle((0, 0, size, size), radius=radius, fill=blue_color)
    
    # Paste lock image
    lock_resized = lock_img.resize((size, size), Image.Resampling.LANCZOS)
    img.alpha_composite(lock_resized)
    
    return img

def create_toolbar_icon(size, lock_img):
    img = lock_img.resize((size, size), Image.Resampling.LANCZOS)
    width, height = img.size
    
    colored_img = Image.new('RGBA', (width, height), (0,0,0,0))
    for y in range(height):
        # Create a gradient so Safari doesn't treat it as a monochrome template image
        r = 50 + int(40 * (y / height))
        g = 150 + int(50 * (y / height))
        b = 250
        
        for x in range(width):
            _, _, _, a = img.getpixel((x, y))
            if a > 0:
                colored_img.putpixel((x, y), (r, g, b, a))
                
    return colored_img

# Load original lock
lock_img = Image.open("ExtensionIcon.png").convert("RGBA")

# 1. Update AppIcon.appiconset
appicon_dir = "Sources/VaultUIApp/Assets.xcassets/AppIcon.appiconset"
for filepath in glob.glob(os.path.join(appicon_dir, "*.png")):
    filename = os.path.basename(filepath)
    parts = filename.split('_')[1].split('x')
    width_str = parts[0]
    scale = 1
    if '@2x' in filename:
        scale = 2
    size = int(width_str) * scale
    
    new_icon = create_app_icon(size, lock_img)
    new_icon.save(filepath)

# 2. Update Safari extension icons (settings)
web_ext_icons_dir = "Sources/VaultSafariExtension/Resources/icons"
for size in [16, 32, 128]:
    filepath = os.path.join(web_ext_icons_dir, f"{size}.png")
    new_icon = create_app_icon(size, lock_img)
    new_icon.save(filepath)

# 3. Update Safari toolbar icons (light blue)
for size in [16, 32]:
    filepath = os.path.join(web_ext_icons_dir, f"toolbar_{size}.png")
    new_icon = create_toolbar_icon(size, lock_img)
    new_icon.save(filepath)

print("Icons generated successfully.")
