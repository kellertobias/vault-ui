import os
import glob
from PIL import Image, ImageDraw

def mask_squircle(image_path):
    img = Image.open(image_path).convert("RGBA")
    size = img.size
    width, height = size
    # Create mask
    mask = Image.new('L', size, 0)
    draw = ImageDraw.Draw(mask)
    # The macOS icon squircle radius is roughly 0.225 of the width
    radius = int(width * 0.225)
    draw.rounded_rectangle((0, 0, width, height), radius=radius, fill=255)
    
    # Apply mask to image (keeping original alpha where it's already transparent, though here we assume it's opaque)
    # We will just replace the alpha channel with the mask.
    r, g, b, a = img.split()
    # If the original image had alpha, we take the minimum of original alpha and the new mask
    # but a simple putalpha(mask) is usually fine if it's currently a solid square with white edges.
    final_alpha = Image.new('L', size)
    for y in range(height):
        for x in range(width):
            final_alpha.putpixel((x, y), min(a.getpixel((x, y)), mask.getpixel((x, y))))
    
    img.putalpha(final_alpha)
    img.save(image_path)

# 1. Fix AppIcons
appicon_dir = "Sources/VaultUIApp/Assets.xcassets/AppIcon.appiconset"
for filepath in glob.glob(os.path.join(appicon_dir, "*.png")):
    mask_squircle(filepath)
    print(f"Masked {filepath}")

# 2. Fix Web Extension icons (which were copied from AppIcon.appiconset before, or generated)
# Actually, the icons in Resources/icons/16.png, 32.png, 128.png are the ones used by manifest.json
web_ext_icons_dir = "Sources/VaultSafariExtension/Resources/icons"
for filename in ["16.png", "32.png", "128.png"]:
    filepath = os.path.join(web_ext_icons_dir, filename)
    if os.path.exists(filepath):
        mask_squircle(filepath)
        print(f"Masked {filepath}")

# 3. Generate toolbar icons from ExtensionIcon.png
ext_icon_path = "ExtensionIcon.png"
if os.path.exists(ext_icon_path):
    ext_icon = Image.open(ext_icon_path).convert("RGBA")
    
    ext_16 = ext_icon.resize((16, 16), Image.Resampling.LANCZOS)
    ext_16.save(os.path.join(web_ext_icons_dir, "toolbar_16.png"))
    
    ext_32 = ext_icon.resize((32, 32), Image.Resampling.LANCZOS)
    ext_32.save(os.path.join(web_ext_icons_dir, "toolbar_32.png"))
    print("Generated toolbar icons.")
