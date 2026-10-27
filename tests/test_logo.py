"""The MOB mark: installed artwork wins, painted fallback still works.

The mark is drawn at 58px in the title bar and 156px on the gate, from one
source. What these check is that the *installed artwork* is what gets drawn
when it exists: the fallback is a stand-in for a fresh checkout, not the
product's identity.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtGui import QColor, QImage, QPixmap                # noqa: E402
from PyQt6.QtWidgets import QApplication                       # noqa: E402

from themob.app.widgets import logo as logo_module             # noqa: E402
from themob.app.widgets.logo import (ASSETS_DIR, MobLogo, MobMark, MobWordmark,
                                     forget_assets, logo_pixmap)  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def clean_cache():
    forget_assets()
    yield
    forget_assets()


@pytest.fixture()
def no_artwork(tmp_path: Path, monkeypatch, clean_cache):
    """Point the loader at an empty directory: the fallback path."""
    monkeypatch.setattr(logo_module, "ASSETS_DIR", tmp_path)
    forget_assets()
    return tmp_path


@pytest.fixture()
def fake_artwork(tmp_path: Path, monkeypatch, clean_cache):
    """A recognisable stand-in asset, so 'was it drawn?' is answerable."""
    image = QImage(60, 70, QImage.Format.Format_ARGB32)
    image.fill(QColor("#ff00ff"))
    path = tmp_path / "mob-logo.png"
    assert image.save(str(path), "PNG")
    monkeypatch.setattr(logo_module, "ASSETS_DIR", tmp_path)
    forget_assets()
    return path


def _colours(widget) -> set[tuple[int, int, int, int]]:
    """Every distinct RGBA in a widget's rendering.

    ``pixelColor``, not ``QColor(image.pixel(...))``: the latter reads the
    packed value as an opaque RGB and silently reports alpha 255 for every
    pixel, which makes a transparency assertion pass for the wrong reason.
    """
    image = widget.grab().toImage().convertToFormat(
        QImage.Format.Format_ARGB32)
    return {image.pixelColor(x, y).getRgb()
            for y in range(image.height())
            for x in range(image.width())}


# ------------------------------------------------------------ the real asset

def test_the_shipped_artwork_is_installed(qapp) -> None:
    """The repository carries the real mark, not only a painted fallback.

    ``qapp`` is required, not decorative: constructing a QPixmap without a
    QApplication aborts the process rather than raising.
    """
    installed = ASSETS_DIR / "mob-logo.png"
    assert installed.is_file(), (
        "no artwork installed: run `python tools/install_logo.py <image>`")
    pixmap = QPixmap(str(installed))
    assert not pixmap.isNull()
    # Portrait, like the hexagon it contains.
    assert pixmap.height() > pixmap.width()


def test_installed_artwork_is_transparent_outside_the_mark(qapp) -> None:
    """A white matte behind the hexagon would sit as a bright box on the dark
    chrome, which is the whole reason the installer keys the background out."""
    image = QPixmap(str(ASSETS_DIR / "mob-logo.png")).toImage().convertToFormat(
        QImage.Format.Format_ARGB32)
    corners = [(0, 0), (image.width() - 1, 0),
               (0, image.height() - 1), (image.width() - 1, image.height() - 1)]
    for x, y in corners:
        assert image.pixelColor(x, y).alpha() == 0, f"corner {x},{y} is opaque"


def test_artwork_is_not_oversized(qapp) -> None:
    """It is drawn at 156px at the largest; a huge file is dead weight."""
    installed = ASSETS_DIR / "mob-logo.png"
    assert installed.stat().st_size < 1_500_000
    pixmap = QPixmap(str(installed))
    assert max(pixmap.width(), pixmap.height()) <= 1024


def test_the_artwork_is_the_photograph_and_not_a_redrawing(qapp) -> None:
    """Guards the thing the user actually objected to.

    A hand-painted approximation of the mark was rejected once; the shipped
    asset has to stay the real image. A drawing has a handful of flat colours,
    a photograph has hundreds of greys, and the violet ring in the O is the
    one deliberate splash of colour in it. Checking all three together is hard
    to satisfy by accident.
    """
    image = QPixmap(str(ASSETS_DIR / "mob-logo.png")).toImage().convertToFormat(
        QImage.Format.Format_ARGB32)

    colours = set()
    greys = 0
    violet = 0
    opaque = 0
    for y in range(0, image.height(), 2):
        for x in range(0, image.width(), 2):
            colour = image.pixelColor(x, y)
            if colour.alpha() < 200:
                continue
            opaque += 1
            red, green, blue = colour.red(), colour.green(), colour.blue()
            colours.add((red, green, blue))
            if abs(red - green) < 8 and abs(green - blue) < 8:
                greys += 1
            if blue > 120 and blue - green > 40 and red < blue:
                violet += 1

    assert opaque > 1000, "the mark is nearly empty"
    assert len(colours) > 100, (
        f"only {len(colours)} distinct colours: this looks like a drawing, "
        "not the photograph")
    assert greys / opaque > 0.9, "the noir photograph should be almost all grey"
    assert violet > 50, "the violet ring in the O is missing"


def test_the_asset_reproduces_from_the_source_image(qapp) -> None:
    """The installer is the only thing that should ever produce this file.

    Skipped where the source image is not present, which is everywhere except
    the machine it was uploaded on. When it is there, re-running the installer
    has to land on the same bytes: that is what makes "this is the exact image,
    just downsized" a checkable claim rather than an assurance.
    """
    import hashlib
    import sys
    import tempfile

    source = Path.home() / "Pictures" / "Screenshots" /         "Screenshot 2026-08-31 165537.png"
    if not source.is_file():
        pytest.skip(f"source image not on this machine: {source.name}")

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from install_logo import install

    rebuilt = install(source, assets_dir=Path(tempfile.mkdtemp()))
    shipped = (ASSETS_DIR / "mob-logo.png").read_bytes()
    assert hashlib.sha256(rebuilt.read_bytes()).hexdigest() ==         hashlib.sha256(shipped).hexdigest(),         "the shipped asset is no longer what the installer produces from the source"


# ------------------------------------------------------- artwork takes priority

def test_mark_draws_the_artwork_when_present(qapp, fake_artwork) -> None:
    assert logo_pixmap() is not None
    assert (255, 0, 255, 255) in _colours(MobMark(size=60)), \
        "the installed artwork should be what is drawn"


def test_logo_draws_the_artwork_when_present(qapp, fake_artwork) -> None:
    assert (255, 0, 255, 255) in _colours(MobLogo(height=120))


def test_logo_adopts_the_artwork_aspect_ratio(qapp, fake_artwork) -> None:
    """Forcing the artwork into the fallback's proportions would letterbox it."""
    widget = MobLogo(height=140)
    assert widget.height() == 140
    assert widget.width() == round(140 * 60 / 70)


def test_mark_is_portrait_not_square(qapp, fake_artwork) -> None:
    # A square box would waste title-bar width on empty margins.
    mark = MobMark(size=40)
    assert mark.height() == 40
    assert mark.width() < mark.height()


def test_the_artwork_is_drawn_without_an_added_outline(qapp, fake_artwork) -> None:
    """The supplied lockup ships as drawn.

    An earlier version painted an accent-coloured silhouette behind the mark so
    its edge would not vanish into the near-black chrome. That reads as a violet
    ring around a logo which already has its own hexagon edge. It is a change
    to the artwork, and the artwork was supplied to be used as-is. The painted
    fallback still gets a halo, because there the silhouette really does vanish.
    """
    from themob.app import theme

    accent = QColor(theme.ACCENT_DIM).getRgb()
    assert accent not in _colours(MobMark(size=60)), \
        "no accent halo may be painted around the installed artwork"
    assert accent not in _colours(MobLogo(height=140))


def test_the_painted_fallback_still_gets_its_halo(qapp, no_artwork) -> None:
    """Without artwork the drawn hexagon is near-black on near-black chrome."""
    from themob.app import theme

    accent = QColor(theme.ACCENT_DIM).getRgb()
    assert accent in _colours(MobMark(size=60))


# -------------------------------------------------------------- the fallback

def test_fallback_paints_when_no_artwork_is_installed(qapp, no_artwork) -> None:
    assert logo_pixmap() is None
    for widget in (MobMark(size=60), MobLogo(height=140), MobWordmark(height=30)):
        widget.grab()          # must not raise, and must not be blank
        assert len(_colours(widget)) > 1


def test_fallback_uses_the_accent_ring(qapp, no_artwork) -> None:
    from themob.app import theme

    assert QColor(theme.ACCENT).getRgb() in _colours(MobMark(size=80))


def test_every_size_paints(qapp) -> None:
    for size in (16, 24, 34, 38, 64, 128):
        MobMark(size=size).grab()
    for height in (40, 90, 156, 240):
        MobLogo(height=height).grab()


def test_a_corrupt_asset_falls_back_instead_of_crashing(
        qapp, tmp_path: Path, monkeypatch, clean_cache) -> None:
    (tmp_path / "mob-logo.png").write_bytes(b"not an image at all")
    monkeypatch.setattr(logo_module, "ASSETS_DIR", tmp_path)
    forget_assets()

    assert logo_pixmap() is None, "an unreadable asset must not be used"
    assert len(_colours(MobMark(size=60))) > 1
