"""Builds router/pcc_router/font.py: bitmap fonts for the router's little screen, which has no font
library. Run on a PC with Pillow, from the repo root:

    python3 router/tools/make_font.py [fonts folder]   (default /usr/share/fonts/google-noto)

The small size uses Noto Sans Mono Condensed Medium: at 12 px the Bold strokes fill in the gaps of
8, 0, 6 and 3, which made addresses hard to read. Medium keeps the same 6 px width, so every page
lays out the same. The medium and large sizes stay Condensed Bold.

Noto Sans Mono is under the SIL Open Font License, which allows embedding it like this.
"""

import base64
import sys

from PIL import Image, ImageDraw, ImageFont

SIZES = {"small": 12, "medium": 17, "large": 28}  # pixel heights that read well on a 76 px tall strip
FILES = {"small": "NotoSansMono-CondensedMedium.ttf", "medium": "NotoSansMono-CondensedBold.ttf",
         "large": "NotoSansMono-CondensedBold.ttf"}
CUT = {"small": 128, "medium": 110, "large": 110}  # how dark an antialiased pixel must be to be lit
CHARS = "".join(chr(c) for c in range(32, 127)) + "·▲▼°"


def build(folder):
    out = ['"""Bitmap fonts for the router screen, made by router/tools/make_font.py from Noto Sans Mono',
           '(SIL Open Font License). Each glyph is rows of bits, packed, base64; all glyphs in a size',
           'share one width (monospace)."""', "", "FONTS = {"]
    for name, px in SIZES.items():
        font = ImageFont.truetype(f"{folder}/{FILES[name]}", px)
        cut = CUT[name]
        asc, desc = font.getmetrics()
        height = asc + desc  # cropped below
        width = max(int(round(font.getlength(c))) for c in CHARS)
        images = {}
        for ch in CHARS:
            im = Image.new("L", (width, height), 0)
            ImageDraw.Draw(im).text((0, 0), ch, font=font, fill=255)
            images[ch] = im
        # crop the empty rows every glyph shares, above the tallest letter and below the lowest
        boxes = [im.point(lambda v: 255 if v >= cut else 0).getbbox() for im in images.values()]
        top = min(b[1] for b in boxes if b)
        bottom = max(b[3] for b in boxes if b)
        height = bottom - top
        glyphs = {}
        for ch, im in images.items():
            im = im.crop((0, top, width, bottom))
            bits = bytearray()
            for y in range(height):
                row = 0
                for x in range(width):
                    row = (row << 1) | (1 if im.getpixel((x, y)) >= cut else 0)
                bits += row.to_bytes((width + 7) // 8, "big")
            glyphs[ch] = base64.b64encode(bytes(bits)).decode()
        out.append(f'    "{name}": {{"w": {width}, "h": {height}, "glyphs": {{')
        for ch, data in glyphs.items():
            out.append(f"        {ch!r}: {data!r},")
        out.append("    }},")
    out.append("}")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "/usr/share/fonts/google-noto"
    with open("router/pcc_router/font.py", "w", encoding="utf-8") as f:
        f.write(build(src))
    print("wrote router/pcc_router/font.py")
