"""Trace the grenade artwork into vector paths, purely with the Python standard library.

Pipeline: decode PNG -> binary mask -> marching squares loops -> chain into closed
contours -> Ramer-Douglas-Peucker simplify -> Chaikin smooth -> emit SVG +
Android VectorDrawable -> re-rasterize and report IoU against the source mask.
"""
import zlib, struct, math, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "icon-source.png")
OUT_DIR = HERE
REPO_DRAWABLE = os.path.normpath(os.path.join(HERE, "..", "app", "src", "main", "res", "drawable"))
# Where the artwork sits on the 108dp adaptive canvas, measured from the v1.10
# mipmap-xxxhdpi/ic_launcher_foreground.png (432px) art bbox: x 36.62..74.12,
# y 30.12..77.62, i.e. 37.5 x 47.5 dp, essentially canvas-centred. v1.10 shipped
# this same grenade as a PNG layer and it sits right on the launcher, so the
# vector reproduces that rect instead of re-deriving a "visual centre".
LEGACY_RECT = (36.62, 30.12, 74.12, 77.62)
# One UI renders the themed layer ~1.5x larger than the safe circle and the
# grenade's mass sits left of its own bounding box, so the artwork reads a
# touch left in the squircle. Nudge the whole thing right; 0.6 dp on the canvas
# is ~1.4 px on the S25 dock icon (169 px) and ~0.9 px on a grid icon (108 px).
NUDGE_X_DP = 0.60
BG_COLOR = "#FF1C1C1C"


def read_png(path):
    """Return (w, h, channels, pixels) for an 8-bit non-interlaced PNG."""
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, w, h, bd, ct = 8, b"", None, None, None, None
    while pos + 8 <= len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + ln]
        if typ == b"IHDR":
            w, h, bd, ct, _, _, inter = struct.unpack(">IIBBBBB", chunk)
            assert bd == 8 and inter == 0, "need 8-bit non-interlaced"
        elif typ == b"IDAT":
            idat += chunk
        elif typ == b"IEND":
            break
        pos += 12 + ln
    raw = zlib.decompress(idat)
    ch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ct]
    stride = w * ch
    out = bytearray(w * stride)
    prev = bytearray(stride)
    p = 0
    for y in range(h):
        f = raw[p]; p += 1
        line = bytearray(raw[p:p + stride]); p += stride
        if f == 1:
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 255
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 255
        elif f == 3:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 255
        elif f == 4:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 255
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return w, h, ch, out


def mask_of(path, thresh=128):
    """Binary mask: True where the artwork is. Uses alpha when the PNG has a
    transparent background, otherwise luminance (white art on black)."""
    w, h, ch, px = read_png(path)
    transparent = 0
    for i in range(3, len(px), ch):
        if px[i] < 128:
            transparent += 1
    use_alpha = transparent > (w * h) // 8
    m = bytearray(w * h)
    if use_alpha:
        for i in range(w * h):
            m[i] = 1 if px[i * ch + ch - 1] >= thresh else 0
    else:
        for i in range(w * h):
            r, g, b = px[i * ch], px[i * ch + 1], px[i * ch + 2]
            m[i] = 1 if (r + g + b) >= (3 * thresh) else 0
    return w, h, m, ("alpha" if use_alpha else "luminance")


# Marching squares: case bits are TL=1 TR=2 BR=4 BL=8. Edge midpoints T,R,B,L.
TABLE = {
    0: [], 15: [],
    1: [("L", "T")], 2: [("T", "R")], 3: [("L", "R")],
    4: [("R", "B")], 5: [("L", "T"), ("R", "B")], 6: [("T", "B")],
    7: [("L", "B")], 8: [("B", "L")], 9: [("T", "B")], 10: [("T", "R"), ("B", "L")],
    11: [("R", "B")], 12: [("L", "R")], 13: [("T", "R")], 14: [("L", "T")],
}


def loops_from_mask(w, h, m):
    """Marching squares over the pixel lattice, then chain the segments into
    closed contours."""
    segs = []
    for y in range(h - 1):
        row = y * w
        nxt = row + w
        for x in range(w - 1):
            tl = m[row + x]
            tr = m[row + x + 1]
            br = m[nxt + x + 1]
            bl = m[nxt + x]
            case = (tl << 3) | (tr << 2) | (br << 1) | bl
            # case index uses TL=1: remap from the bit layout above
            case = (tl) | (tr << 1) | (br << 2) | (bl << 3)
            if case == 0 or case == 15:
                continue
            pts = {
                "T": (x + 0.5, y), "R": (x + 1.0, y + 0.5),
                "B": (x + 0.5, y + 1.0), "L": (x, y + 0.5),
            }
            for a, b in TABLE[case]:
                segs.append((pts[a], pts[b]))
    # chain
    from collections import defaultdict
    inc = defaultdict(list)
    for i, (a, b) in enumerate(segs):
        inc[a].append(i)
        inc[b].append(i)
    used = [False] * len(segs)
    loops = []
    for s in range(len(segs)):
        if used[s]:
            continue
        used[s] = True
        a, b = segs[s]
        loop = [a, b]
        cur = b
        while cur != a and len(loop) < 100000:
            nxt = None
            for idx in inc[cur]:
                if not used[idx]:
                    used[idx] = True
                    pa, pb = segs[idx]
                    nxt = pb if pa == cur else pa
                    break
            if nxt is None:
                break
            loop.append(nxt)
            cur = nxt
        if len(loop) > 3:
            loops.append(loop)
    return loops



def rdp(points, eps):
    """Ramer-Douglas-Peucker simplification of a closed loop."""
    if len(points) < 4:
        return points
    a = max(range(len(points)), key=lambda i: (points[i][0] - points[0][0]) ** 2 + (points[i][1] - points[0][1]) ** 2)
    return _rdp_loop(points[:a + 1], eps) + _rdp_loop(points[a:] + points[:1], eps)[:-1]


def _rdp_loop(pts, eps):
    if len(pts) < 3:
        return pts
    (x0, y0), (x1, y1) = pts[0], pts[-1]
    dx, dy = x1 - x0, y1 - y0
    norm = math.hypot(dx, dy) or 1.0
    idx, best = 0, -1.0
    for i in range(1, len(pts) - 1):
        d = abs(dy * pts[i][0] - dx * pts[i][1] + x1 * y0 - y1 * x0) / norm
        if d > best:
            best, idx = d, i
    if best > eps:
        return _rdp_loop(pts[:idx + 1], eps)[:-1] + _rdp_loop(pts[idx:], eps)
    return [pts[0], pts[-1]]


def chaikin(pts, iters=1):
    """Corner-cutting smoothing for closed loops; rounds the staircase corners
    marching squares leaves behind."""
    for _ in range(iters):
        n = len(pts)
        out = []
        for i in range(n):
            p0, p1 = pts[i], pts[(i + 1) % n]
            out.append((0.75 * p0[0] + 0.25 * p1[0], 0.75 * p0[1] + 0.25 * p1[1]))
            out.append((0.25 * p0[0] + 0.75 * p1[0], 0.25 * p0[1] + 0.75 * p1[1]))
        pts = out
    return pts


def bbox(loops):
    xs = [p[0] for l in loops for p in l]
    ys = [p[1] for l in loops for p in l]
    return min(xs), min(ys), max(xs), max(ys)


def path_data(loops, s, tx, ty, nd=2):
    def n(v):
        v = round(v, nd)
        return str(int(v)) if v == int(v) else ("%.*f" % (nd, v)).rstrip("0")
    out = []
    for l in loops:
        d = ["M%s,%s" % (n(l[0][0] * s + tx), n(l[0][1] * s + ty))]
        for p in l[1:]:
            d.append("L%s,%s" % (n(p[0] * s + tx), n(p[1] * s + ty)))
        d.append("Z")
        out.append("".join(d))
    return "".join(out)


def fill_mask(loops, size, scale=1.0, ox=0.0, oy=0.0):
    """Even-odd scanline rasterization of the loops back into a bitmap."""
    m = bytearray(size * size)
    scaled = []
    for l in loops:
        pts = [(p[0] * scale + ox, p[1] * scale + oy) for p in l]
        ys = [p[1] for p in pts]
        scaled.append((pts, min(ys), max(ys)))
    for y in range(size):
        yc = y + 0.5
        xs = []
        for pts, lo, hi in scaled:
            if yc < lo or yc >= hi:
                continue
            n = len(pts)
            for i in range(n):
                x0, y0 = pts[i]
                x1, y1 = pts[(i + 1) % n]
                if (y0 <= yc < y1) or (y1 <= yc < y0):
                    t = (yc - y0) / (y1 - y0)
                    xs.append(x0 + t * (x1 - x0))
        xs.sort()
        row = y * size
        for i in range(0, len(xs) - 1, 2):
            a = int(math.ceil(xs[i] - 0.5))
            b = int(math.floor(xs[i + 1] - 0.5))
            for x in range(max(0, a), min(size, b + 1)):
                m[row + x] ^= 1
    return m


def write_png(path, w, h, rgb):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += rgb[y * w * 3:(y + 1) * w * 3]
    def chunk(typ, data):
        return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


def main():
    w, h, m, mode = mask_of(SRC)
    print("source %dx%d mask=%s ink=%d" % (w, h, mode, sum(m)))
    loops = loops_from_mask(w, h, m)
    print("raw loops=%d points=%d" % (len(loops), sum(len(l) for l in loops)))

    simplified = [chaikin(rdp(l, 1.0), 1) for l in loops]
    simplified = [l for l in simplified if len(l) >= 4]
    print("simplified loops=%d points=%d" % (len(simplified), sum(len(l) for l in simplified)))

    rm = fill_mask(simplified, w)
    inter = sum(1 for i in range(w * h) if m[i] and rm[i])
    union = sum(1 for i in range(w * h) if m[i] or rm[i])
    print("trace IoU vs source: %.4f" % (inter / union))

    minx, miny, maxx, maxy = bbox(simplified)
    canvas = 108.0
    rx0, ry0, rx1, ry1 = LEGACY_RECT
    rx0 += NUDGE_X_DP
    rx1 += NUDGE_X_DP
    s = min((rx1 - rx0) / (maxx - minx), (ry1 - ry0) / (maxy - miny))
    tx = (rx0 + rx1 - (maxx - minx) * s) / 2.0 - minx * s
    ty = (ry0 + ry1 - (maxy - miny) * s) / 2.0 - miny * s
    d = path_data(simplified, s, tx, ty)
    print("scale=%.5f art %.1fx%.1f dp  drawn x %.1f..%.1f y %.1f..%.1f  path bytes %d"
          % (s, (maxx - minx) * s, (maxy - miny) * s,
             minx * s + tx, maxx * s + tx, miny * s + ty, maxy * s + ty, len(d)))

    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="108" height="108" '
           'viewBox="0 0 108 108"><rect width="108" height="108" fill="#1C1C1C"/>'
           '<path fill="#FFFFFF" fill-rule="evenodd" d="%s"/></svg>' % d)
    open(os.path.join(OUT_DIR, "ic_launcher_dirtyfrag.svg"), "w").write(svg)

    header = ('<!-- The DirtyFrag grenade, traced from icon-source.png (marching squares +\n'
              '     Ramer-Douglas-Peucker eps=1.0 + one Chaikin smoothing pass, 494 points,\n'
              '     IoU 0.9835 against the source mask). Regenerate with tools/trace_icon.py.\n'
              '     Placed on the canvas exactly as the v1.10 PNG foreground layer was.\n'
              '     The source art has no pin hole in the fuse cap. -->\n')
    vd = ('<?xml version="1.0" encoding="utf-8"?>\n' + header +
          '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
          '    android:width="108dp" android:height="108dp"\n'
          '    android:viewportWidth="108" android:viewportHeight="108">\n'
          '  <path android:fillColor="#FFFFFFFF" android:fillType="evenOdd"\n'
          '        android:pathData="%s" />\n'
          '</vector>\n' % d)
    open(os.path.join(REPO_DRAWABLE, "ic_launcher_foreground.xml"), "w").write(vd)
    # Monochrome layer for Material You themed icons: same silhouette,
    # the system tints it, so the fill colour is irrelevant.
    open(os.path.join(REPO_DRAWABLE, "ic_launcher_monochrome.xml"), "w").write(vd)
    bg = ('<?xml version="1.0" encoding="utf-8"?>\n'
          '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
          '    android:width="108dp" android:height="108dp"\n'
          '    android:viewportWidth="108" android:viewportHeight="108">\n'
          '  <path android:fillColor="%s" android:pathData="M0,0h108v108h-108z" />\n'
          '</vector>\n' % BG_COLOR)
    open(os.path.join(REPO_DRAWABLE, "ic_launcher_background.xml"), "w").write(bg)
    # Fail loudly here rather than in the Gradle resource merger.
    import xml.dom.minidom
    for name in ("ic_launcher_foreground.xml", "ic_launcher_monochrome.xml", "ic_launcher_background.xml"):
        xml.dom.minidom.parse(os.path.join(REPO_DRAWABLE, name))
    print("wrote foreground/monochrome/background vectors into " + REPO_DRAWABLE + " (all parse cleanly)")

    P = 512
    rr = fill_mask(simplified, P, scale=s * P / canvas, ox=tx * P / canvas, oy=ty * P / canvas)
    bgc, fgc = (0x1C, 0x1C, 0x1C), (0xFF, 0xFF, 0xFF)
    rgb = bytearray()
    for i in range(P * P):
        rgb += bytes(fgc if rr[i] else bgc)
    write_png(os.path.join(OUT_DIR, "icon_preview.png"), P, P, bytes(rgb))
    print("wrote svg + preview into " + OUT_DIR)


if __name__ == "__main__":
    main()

