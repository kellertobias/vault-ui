import os
import glob
from PIL import Image, ImageDraw

def apply_squircle_mask(img):
    img = img.convert("RGBA")
    width, height = img.size
    
    # Create mask
    mask = Image.new('L', (width, height), 0)
    draw = ImageDraw.Draw(mask)
    radius = int(width * 0.225)
    draw.rounded_rectangle((0, 0, width, height), radius=radius, fill=255)
    
    # Apply mask
    r, g, b, a = img.split()
    final_alpha = Image.new('L', (width, height))
    for y in range(height):
        for x in range(width):
            final_alpha.putpixel((x, y), min(a.getpixel((x, y)), mask.getpixel((x, y))))
    
    img.putalpha(final_alpha)
    return img

original_dir = "build_icns/AppIcon.iconset"
dest_appicon = "Sources/VaultUIApp/Assets.xcassets/AppIcon.appiconset"
dest_web_icons = "Sources/VaultSafariExtension/Resources/icons"

# 1. Update AppIcon.appiconset
for filepath in glob.glob(os.path.join(original_dir, "*.png")):
    filename = os.path.basename(filepath)
    dest_name = filename
    if '@' not in filename:
        name_part, ext = os.path.splitext(filename)
        dest_name = f"{name_part}@1x{ext}"
    
    dest_path = os.path.join(dest_appicon, dest_name)
    
    # Ensure it's a file we want to overwrite
    if os.path.exists(dest_path):
        img = Image.open(filepath)
        masked = apply_squircle_mask(img)
        masked.save(dest_path)

# 2. Update Safari extension settings icons
size_map = {
    16: "icon_16x16.png",
    32: "icon_32x32.png",
    128: "icon_128x128.png"
}
for size, orig_name in size_map.items():
    orig_path = os.path.join(original_dir, orig_name)
    if os.path.exists(orig_path):
        img = Image.open(orig_path)
        masked = apply_squircle_mask(img)
        masked.save(os.path.join(dest_web_icons, f"{size}.png"))
        
        # 3. Update Safari toolbar icons
        if size in [16, 32]:
            masked.save(os.path.join(dest_web_icons, f"toolbar_{size}.png"))

print("Restored original icons with squircle mask.")
