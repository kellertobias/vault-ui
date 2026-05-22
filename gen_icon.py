from PIL import Image, ImageDraw

img = Image.new('RGBA', (512, 512), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Lock body
draw.rounded_rectangle([126, 230, 386, 450], radius=30, fill=(255, 255, 255, 255))

# Lock shackle
# Arc bounding box: left, top, right, bottom
draw.arc([166, 90, 346, 270], start=180, end=0, fill=(255, 255, 255, 255), width=45)
draw.line([166, 180, 166, 230], fill=(255, 255, 255, 255), width=45)
draw.line([346, 180, 346, 230], fill=(255, 255, 255, 255), width=45)

# Cut out keyhole (by drawing transparent over it? Pillow doesn't support erasing with draw, but we can do pixel manipulation)
for y in range(230, 450):
    for x in range(126, 386):
        # Ellipse for keyhole head
        if (x - 256)**2 + (y - 320)**2 <= 20**2:
            img.putpixel((x, y), (0, 0, 0, 0))
        # Triangle for keyhole base
        if 320 <= y <= 370 and 256 - (y - 320)*0.3 <= x <= 256 + (y - 320)*0.3:
            img.putpixel((x, y), (0, 0, 0, 0))

img.save('ExtensionIcon.png')
