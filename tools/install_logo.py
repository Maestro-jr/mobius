"""Install the MOB logo as themob's application asset.

Takes the logo as an image: a screenshot is fine, and turns it into the
transparent PNG the UI draws:

    python tools/install_logo.py path/to/logo.png

What it does, and why each step is needed:

1. **Flood-fill the background to transparent, from the edges inward.** The
   mark sets white ``M O B`` letters on a black hexagon, so a global
   "replace white with alpha" would punch holes straight through the wordmark.
   Filling from the border only removes background that is actually connected
   to the outside.
2. **Crop to what is left.** A screenshot carries whatever else was on screen;
   only the mark's own bounding box is kept.
3. **Downscale to a sane maximum.** The console draws it at 34px and 132px;
   carrying a 4K original would just cost memory.

Re-runnable: pass a new image and it replaces the installed one. Requires
Pillow, which is a development dependency, not a runtime one, the app itself
only needs the resulting PNG.
"""
from __future__ import annotations

import argparse
import sys
from collections import deque
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = REPO_ROOT / "themob" / "app" / "assets"
LOGO_NAME = "mob-logo.png"

# How far a pixel may sit from the sampled background colour and still count as
# background. Generous enough for JPEG ringing and anti-aliased screenshots,
# tight enough not to eat the mark's own dark edge.
DEFAULT_TOLERANCE = 28

# The mark is drawn at 132px at the largest; 1024 leaves room for a high-DPI
# display without carrying a needlessly large file.
DEFAULT_MAX_SIZE = 1024


def _load(path: Path):
    from PIL import Image

    try:
        image = Image.open(path)
    except OSError as exc:
        raise SystemExit(f"could not read {path}: {exc}") from exc
    return image.convert("RGBA")


#: A pixel this transparent is background regardless of its colour.
_ALPHA_FLOOR = 8
#: An opaque colour must cover at least this share of the border to be treated
#: as the background; below it, the border is picture content, not a matte.
_BORDER_SHARE = 0.5


def _background_mask(array, tolerance: int):
    """Which pixels *could* be background, by colour alone.

    Two things count, and a screenshot of a logo routinely has both: pixels
    that are already transparent, and pixels matching whatever opaque colour
    dominates the border. Sampling only the corners is not enough, an image
    can have transparent corners and an opaque white page behind the mark,
    and keying on the corner alone then matches the mark's own black.
    """
    import numpy as np

    alpha = array[..., 3]
    rgb = array[..., :3].astype(np.int16)
    transparent = alpha <= _ALPHA_FLOOR

    border = np.zeros(alpha.shape, dtype=bool)
    border[0, :] = border[-1, :] = True
    border[:, 0] = border[:, -1] = True
    opaque_border = border & ~transparent

    described = ["transparent"]
    mask = transparent.copy()
    if opaque_border.any():
        colours, counts = np.unique(rgb[opaque_border], axis=0, return_counts=True)
        dominant = colours[counts.argmax()]
        share = counts.max() / counts.sum()
        if share >= _BORDER_SHARE:
            distance = np.abs(rgb - dominant.astype(np.int16)).max(axis=2)
            mask |= (distance <= tolerance) & ~transparent
            described.append(f"rgb{tuple(int(c) for c in dominant)} "
                             f"({share:.0%} of the border)")
    print(f"  background: {', '.join(described)}")
    return mask


def _flood_fill_background(image, tolerance: int):
    """Make every background pixel *reachable from the border* transparent.

    Reachability is the point: the mark sets white letters on a black hexagon,
    so removing every white pixel would hollow out the wordmark. Only
    background connected to the outside is removed.
    """
    import numpy as np

    array = np.array(image)
    height, width = array.shape[:2]
    candidate = _background_mask(array, tolerance)

    flat = candidate.reshape(-1)
    seen = np.zeros(height * width, dtype=bool)
    queue: deque[int] = deque()

    def push(index: int) -> None:
        if flat[index] and not seen[index]:
            seen[index] = True
            queue.append(index)

    for x in range(width):
        push(x)
        push((height - 1) * width + x)
    for y in range(height):
        push(y * width)
        push(y * width + width - 1)

    while queue:
        index = queue.popleft()
        y, x = divmod(index, width)
        if x > 0:
            push(index - 1)
        if x < width - 1:
            push(index + 1)
        if y > 0:
            push(index - width)
        if y < height - 1:
            push(index + width)

    removed = seen.reshape(height, width)
    array[removed] = (0, 0, 0, 0)
    print(f"  {int(removed.sum()):,} px made transparent")

    from PIL import Image
    return Image.fromarray(array, "RGBA")


def _crop_to_content(image):
    box = image.getbbox()
    if box is None:
        raise SystemExit("the image is entirely transparent after keying")
    cropped = image.crop(box)
    print(f"  cropped to {cropped.width}x{cropped.height} "
          f"(from {image.width}x{image.height})")
    return cropped


def _downscale(image, max_size: int):
    from PIL import Image

    if max(image.size) <= max_size:
        return image
    scale = max_size / max(image.size)
    resized = image.resize(
        (max(1, round(image.width * scale)), max(1, round(image.height * scale))),
        Image.LANCZOS)
    print(f"  downscaled to {resized.width}x{resized.height}")
    return resized


def install(source: Path, *, tolerance: int = DEFAULT_TOLERANCE,
            max_size: int = DEFAULT_MAX_SIZE, keep_background: bool = False,
            assets_dir: Path = ASSETS_DIR) -> Path:
    print(f"reading {source}")
    image = _load(source)
    print(f"  {image.width}x{image.height}")

    if not keep_background:
        image = _flood_fill_background(image, tolerance)
    image = _crop_to_content(image)
    image = _downscale(image, max_size)

    assets_dir.mkdir(parents=True, exist_ok=True)
    destination = assets_dir / LOGO_NAME
    image.save(destination, "PNG", optimize=True)
    print(f"installed {destination} ({destination.stat().st_size:,} bytes)")
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/install_logo.py",
        description="Install the MOB logo as themob's application asset.")
    parser.add_argument("image", type=Path, help="the logo image (PNG/JPG/WebP)")
    parser.add_argument("--tolerance", type=int, default=DEFAULT_TOLERANCE,
                        help="how close a pixel must be to the corner colour to "
                             f"count as background (default {DEFAULT_TOLERANCE})")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE,
                        help=f"longest edge after downscaling (default {DEFAULT_MAX_SIZE})")
    parser.add_argument("--keep-background", action="store_true",
                        help="do not key out the background (for an image that "
                             "already has transparency)")
    args = parser.parse_args(argv)

    if not args.image.is_file():
        print(f"no such file: {args.image}", file=sys.stderr)
        return 2
    try:
        install(args.image, tolerance=args.tolerance, max_size=args.max_size,
                keep_background=args.keep_background)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
