import os
import glob
import math
from PIL import Image, ImageDraw

def apply_glare_and_squircle(img):
    img = img.convert("RGBA")
    width, height = img.size
    
    # 1. Apply Bluish Glare
    center_x, center_y = width / 2, height / 2
    max_dist = math.hypot(center_x, center_y)
    
    # We will modify pixels in place
    pixels = img.load()
    for y in range(height):
        for x in range(width):
            r, g, b, a = pixels[x, y]
            if a > 0:
                dist = math.hypot(x - center_x, y - center_y)
                # intensity falls off towards the edges
                intensity = max(0, 1.0 - (dist / max_dist))
                
                # Add blue glare (r:15, g:35, b:70 at center) for a nice premium dark blue glow
                r_add = int(15 * intensity)
                g_add = int(35 * intensity)
                b_add = int(70 * intensity)
                
                new_r = min(255, r + r_add)
                new_g = min(255, g + g_add)
                new_b = min(255, b + b_add)
                pixels[x, y] = (new_r, new_g, new_b, a)
                
    # 2. Apply Squircle Mask
    mask = Image.new('L', (width, height), 0)
    draw = ImageDraw.Draw(mask)
    radius = int(width * 0.225)
    draw.rounded_rectangle((0, 0, width, height), radius=radius, fill=255)
    
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
    if os.path.exists(dest_path):
        img = Image.open(filepath)
        masked = apply_glare_and_squircle(img)
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
        masked = apply_glare_and_squircle(img)
        masked.save(os.path.join(dest_web_icons, f"{size}.png"))
        
        # 3. Update Safari toolbar icons
        if size in [16, 32]:
            masked.save(os.path.join(dest_web_icons, f"toolbar_{size}.png"))

print("Restored icons with bluish glare and squircle mask.")
