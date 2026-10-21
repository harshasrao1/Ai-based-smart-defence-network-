"""Generate crisp multi-resolution binary favicon.ico and favicon.png."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

FRONTEND = Path(__file__).resolve().parents[2] / 'frontend'

def make_icon(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    scale = size / 64.0
    
    # Outer shield polygon
    pts = [
        (32 * scale, 3 * scale),
        (55 * scale, 12 * scale),
        (55 * scale, 32 * scale),
        (32 * scale, 60 * scale),
        (9 * scale, 32 * scale),
        (9 * scale, 12 * scale),
    ]
    # Dark navy background
    draw.polygon(pts, fill=(10, 24, 38, 255))
    
    # Inner glowing fill
    inner_pts = [
        (32 * scale, 8 * scale),
        (50 * scale, 15 * scale),
        (50 * scale, 30 * scale),
        (32 * scale, 52 * scale),
        (14 * scale, 30 * scale),
        (14 * scale, 15 * scale),
    ]
    draw.polygon(inner_pts, fill=(16, 50, 66, 255))
    
    # Cyan border
    border_w = max(1, int(3 * scale))
    draw.polygon(pts, outline=(77, 226, 224, 255), width=border_w)
    
    # Text "SD"
    font_size = max(10, int(22 * scale))
    font = None
    for font_name in ['arialbd.ttf', 'seguiemb.ttf', 'segoeuib.ttf', 'arial.ttf']:
        try:
            font = ImageFont.truetype(font_name, font_size)
            break
        except OSError:
            continue
    if font is None:
        font = ImageFont.load_default()
    
    # Draw glowing cyan / white SD text
    draw.text((32 * scale, 30 * scale), 'SD', fill=(255, 255, 255, 255), anchor='mm', font=font)
    
    # Tiny security dot
    dot_r = max(1.0, 2.0 * scale)
    draw.ellipse([
        (32 * scale - dot_r, 47 * scale - dot_r),
        (32 * scale + dot_r, 47 * scale + dot_r)
    ], fill=(77, 226, 224, 255))
    
    return img

def main():
    img64 = make_icon(64)
    img48 = make_icon(48)
    img32 = make_icon(32)
    img16 = make_icon(16)
    
    FRONTEND.mkdir(parents=True, exist_ok=True)
    ico_path = FRONTEND / 'favicon.ico'
    png_path = FRONTEND / 'favicon.png'
    png32_path = FRONTEND / 'favicon-32x32.png'
    
    img64.save(ico_path, format='ICO', sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
    img64.save(png_path, format='PNG')
    img32.save(png32_path, format='PNG')
    print(f'Successfully generated {ico_path} and PNG favicons!')

if __name__ == '__main__':
    main()
