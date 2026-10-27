"""The MOB mark: the hexagon, the noir plate, and the violet ``O``.

Three pieces, following HiveDefend's split between a compact mark (``HDMark``)
and a wordmark (``HivedLogo``):

* :class:`MobMark`: the hexagon with the violet ring. Title bar, tabs.
* :class:`MobWordmark`: ``The`` over ``M O B``, the ``O`` a violet ring.
* :class:`MobLogo`: the full lockup: hexagon, noir plate, both texts.

All of it is painted, not an image: the mark is a title-bar icon at 34px and a
splash at 190px in the same session, and a raster would be soft at one of them.

**The real artwork wins.** When ``themob/app/assets/mob-logo.png`` exists it is
drawn as-is, scaled: the shipped mark, not an approximation of it. Install it
with ``python tools/install_logo.py <image>``, which keys out the background and
crops to the mark.

The painted fallback below only runs when that asset is missing, so the app
still has a mark in a fresh checkout. A plate-only image at
``assets/mob-plate.png`` fills just the hexagon's interior, for the same reason.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt
from PyQt6.QtGui import (QBrush, QColor, QFont, QFontMetricsF, QLinearGradient,
                         QPainter, QPainterPath, QPen, QPixmap, QPolygonF,
                         QRadialGradient)
from PyQt6.QtWidgets import QSizePolicy, QWidget

from .. import theme

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
#: The complete lockup: hexagon, plate and both texts, drawn as-is when present.
_LOGO_STEMS = ("mob-logo",)
#: Just the photographic interior, composited into the painted hexagon.
_PLATE_STEMS = ("mob-plate",)
_ASSET_SUFFIXES = (".png", ".jpg", ".jpeg", ".webp")

# A flat-top hexagon, normalised to its own bounding box: flat top and bottom
# edges, points at left and right on the half-line. The widget is taller than
# it is wide (see ``_ASPECT``), which is what stretches this into the MOB
# mark's silhouette. Tapering the lower vertices toward a point turns it into a
# diamond, which is not the shape.
_HEX: tuple[tuple[float, float], ...] = (
    (0.25, 0.00),
    (0.75, 0.00),
    (1.00, 0.50),
    (0.75, 1.00),
    (0.25, 1.00),
    (0.00, 0.50),
)

# Width as a fraction of height. Matches the proportions of the MOB mark.
_ASPECT = 0.86

# The photographic plate sits inside the widest band of the hexagon, text over it.
_PLATE = (0.10, 0.22, 0.90, 0.64)          # left, top, right, bottom (normalised)

# Below this the noir figure is mud rather than detail, so the mark drops it.
_FIGURE_MIN_HEIGHT = 56.0

_MONO_STACK = ("Consolas", "Cascadia Mono", "DejaVu Sans Mono", "Courier New")

_plate_cache: dict[str, Optional[QPixmap]] = {}


# --------------------------------------------------------------------- helpers

def hexagon(rect: QRectF) -> QPolygonF:
    """The mark's hexagon, scaled into *rect*."""
    return QPolygonF([
        QPointF(rect.x() + fx * rect.width(), rect.y() + fy * rect.height())
        for fx, fy in _HEX
    ])


def mono_font(pixel_size: float, weight: QFont.Weight = QFont.Weight.Normal,
              spacing: float = 0.0) -> QFont:
    """A typewriter face at an exact pixel size, with optional letter-spacing."""
    font = QFont()
    font.setFamilies(list(_MONO_STACK))
    font.setStyleHint(QFont.StyleHint.TypeWriter)
    font.setPixelSize(max(1, int(round(pixel_size))))
    font.setWeight(weight)
    if spacing:
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, spacing)
    return font


def _asset(key: str, stems: tuple[str, ...]) -> Optional[QPixmap]:
    """The first readable asset matching *stems*, cached after the first look."""
    if key in _plate_cache:
        return _plate_cache[key]
    found: Optional[QPixmap] = None
    for stem in stems:
        for suffix in _ASSET_SUFFIXES:
            candidate = ASSETS_DIR / f"{stem}{suffix}"
            if candidate.is_file():
                pixmap = QPixmap(str(candidate))
                if not pixmap.isNull():
                    found = pixmap
                    break
        if found is not None:
            break
    _plate_cache[key] = found
    return found


def app_icon():
    """The window and taskbar icon, from the shipped artwork.

    This is what a hover preview and the taskbar show. Without it themob is an
    unnamed blank next to every other program, which is what prompted adding it.
    Returns None when no artwork is installed, so the caller can simply skip
    setting an icon rather than setting an empty one.
    """

    from PyQt6.QtGui import QIcon

    pixmap = logo_pixmap()
    return QIcon(pixmap) if pixmap is not None else None


def logo_pixmap() -> Optional[QPixmap]:
    """The complete MOB lockup, if the artwork has been installed."""
    return _asset("logo", _LOGO_STEMS)


def plate_pixmap() -> Optional[QPixmap]:
    """The photographic plate alone, for compositing into the painted hexagon."""
    return _asset("plate", _PLATE_STEMS)


def forget_assets() -> None:
    """Drop the asset cache: used by the tests, and after installing artwork."""
    _plate_cache.clear()


def _silhouette(pixmap: QPixmap, color: str) -> QPixmap:
    """A flat *color* copy of *pixmap*, keeping its alpha.

    ``CompositionMode_SourceIn`` paints only where the source is opaque, so the
    result is the artwork's own outline rather than a box around it.
    """
    tinted = QPixmap(pixmap.size())
    tinted.fill(Qt.GlobalColor.transparent)
    painter = QPainter(tinted)
    painter.drawPixmap(0, 0, pixmap)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(tinted.rect(), QColor(color))
    painter.end()
    return tinted


def _draw_scaled(painter: QPainter, pixmap: QPixmap, box: QRectF, *,
                 halo: str | None = theme.ACCENT_DIM) -> None:
    """Draw *pixmap* to fit *box*, centred, preserving its aspect ratio.

    The mark is a black hexagon and the chrome behind it is near-black, so its
    silhouette disappears at the edges. A thin halo in the accent colour gives
    it back without touching the artwork itself. Pass ``halo=None`` to skip it.
    """
    scaled = pixmap.scaled(box.size().toSize(),
                           Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
    x = int(box.x() + (box.width() - scaled.width()) / 2)
    y = int(box.y() + (box.height() - scaled.height()) / 2)

    if halo:
        outline = _silhouette(scaled, halo)
        spread = 1 if scaled.height() < 80 else 2
        for dx, dy in ((-spread, 0), (spread, 0), (0, -spread), (0, spread),
                       (-spread, -spread), (spread, -spread),
                       (-spread, spread), (spread, spread)):
            painter.drawPixmap(x + dx, y + dy, outline)

    painter.drawPixmap(x, y, scaled)


def _paint_noir_plate(painter: QPainter, rect: QRectF) -> None:
    """A fedora-and-trenchcoat silhouette, hard-lit from the left.

    The stand-in for the photographic plate. Deliberately low-contrast so the
    ``The`` and ``M O B`` set over it stay readable at any size.
    """
    painter.save()
    # IntersectClip, not the default ReplaceClip: the caller has already
    # clipped to the hexagon and replacing that lets the plate spill out.
    painter.setClipRect(rect, Qt.ClipOperation.IntersectClip)
    painter.setPen(Qt.PenStyle.NoPen)

    backdrop = QLinearGradient(rect.topLeft(), rect.bottomRight())
    backdrop.setColorAt(0.0, QColor("#191b22"))
    backdrop.setColorAt(0.45, QColor("#0c0e13"))
    backdrop.setColorAt(1.0, QColor("#030406"))
    painter.fillRect(rect, QBrush(backdrop))

    width, height = rect.width(), rect.height()
    cx = rect.x() + width * 0.5
    figure = QColor("#9aa0ab")

    # Shoulders and coat: a trapezoid rising to the collar.
    coat = QPainterPath()
    coat.moveTo(cx - width * 0.42, rect.bottom())
    coat.lineTo(cx - width * 0.30, rect.y() + height * 0.60)
    coat.quadTo(cx - width * 0.16, rect.y() + height * 0.47,
                cx - width * 0.07, rect.y() + height * 0.46)
    coat.lineTo(cx + width * 0.07, rect.y() + height * 0.46)
    coat.quadTo(cx + width * 0.16, rect.y() + height * 0.47,
                cx + width * 0.30, rect.y() + height * 0.60)
    coat.lineTo(cx + width * 0.42, rect.bottom())
    coat.closeSubpath()
    painter.setBrush(QBrush(QColor(figure.red(), figure.green(), figure.blue(), 70)))
    painter.drawPath(coat)

    # Head, then the fedora: a tall pinched crown over a narrow snapped brim.
    # A wide flat brim reads as a flying saucer, which is the failure mode here.
    painter.setBrush(QBrush(QColor(figure.red(), figure.green(), figure.blue(), 52)))
    painter.drawEllipse(QRectF(cx - width * 0.080, rect.y() + height * 0.22,
                               width * 0.16, height * 0.28))
    crown = QPainterPath()
    crown.moveTo(cx - width * 0.125, rect.y() + height * 0.30)
    crown.lineTo(cx - width * 0.105, rect.y() + height * 0.10)
    crown.quadTo(cx - width * 0.055, rect.y() + height * 0.03,
                 cx, rect.y() + height * 0.055)
    crown.quadTo(cx + width * 0.055, rect.y() + height * 0.03,
                 cx + width * 0.105, rect.y() + height * 0.10)
    crown.lineTo(cx + width * 0.125, rect.y() + height * 0.30)
    crown.closeSubpath()
    painter.setBrush(QBrush(QColor(figure.red(), figure.green(), figure.blue(), 92)))
    painter.drawPath(crown)
    brim = QPainterPath()
    brim.moveTo(cx - width * 0.185, rect.y() + height * 0.295)
    brim.quadTo(cx, rect.y() + height * 0.235, cx + width * 0.185,
                rect.y() + height * 0.295)
    brim.quadTo(cx, rect.y() + height * 0.375, cx - width * 0.185,
                rect.y() + height * 0.295)
    brim.closeSubpath()
    painter.drawPath(brim)

    # Hard rim light from the left, then a vignette to sink the corners.
    rim = QLinearGradient(rect.left(), 0, rect.left() + width * 0.55, 0)
    rim.setColorAt(0.0, QColor(255, 255, 255, 46))
    rim.setColorAt(1.0, QColor(255, 255, 255, 0))
    painter.fillRect(rect, QBrush(rim))

    vignette = QRadialGradient(rect.center(), max(width, height) * 0.72)
    vignette.setColorAt(0.55, QColor(0, 0, 0, 0))
    vignette.setColorAt(1.0, QColor(0, 0, 0, 215))
    painter.fillRect(rect, QBrush(vignette))

    # Fade the foot into the surrounding black so the plate reads as inset
    # rather than as a pasted-on rectangle.
    foot = QLinearGradient(0, rect.bottom() - height * 0.22, 0, rect.bottom())
    foot.setColorAt(0.0, QColor(0, 0, 0, 0))
    foot.setColorAt(1.0, QColor(0, 0, 0, 235))
    painter.fillRect(rect, QBrush(foot))
    painter.restore()


def _paint_ring(painter: QPainter, center: QPointF, radius: float,
                thickness: float, color: str = theme.ACCENT) -> None:
    """The violet ``O``: a ring, not a filled disc."""
    pen = QPen(QColor(color), max(1.4, thickness))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawEllipse(center, radius, radius)


def _paint_mob(painter: QPainter, center: QPointF, cap_height: float,
               color: str = "#ffffff") -> float:
    """``M`` ring ``B`` centred on *center*. Returns the lockup's width.

    The letters are measured rather than positioned by guess, so the ring lands
    on the optical centre at every size.
    """
    font = mono_font(cap_height, QFont.Weight.Bold)
    painter.setFont(font)
    metrics = QFontMetricsF(font)
    m_width = metrics.horizontalAdvance("M")
    b_width = metrics.horizontalAdvance("B")
    radius = cap_height * 0.30
    gap = cap_height * 0.24
    total = m_width + gap + 2 * radius + gap + b_width

    left = center.x() - total / 2
    baseline = center.y() + cap_height * 0.36

    painter.setPen(QColor(color))
    painter.drawText(QPointF(left, baseline), "M")
    _paint_ring(painter,
                QPointF(left + m_width + gap + radius, center.y()),
                radius, cap_height * 0.11)
    painter.drawText(QPointF(left + m_width + gap + 2 * radius + gap, baseline), "B")
    return total


# ----------------------------------------------------------------------- marks

class MobMark(QWidget):
    """The compact mark: the installed artwork, or a painted stand-in."""

    def __init__(self, size: int = 34, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._size = size
        # The mark is taller than it is wide, so the widget is too. Boxing it
        # into a square would letterbox the artwork and waste title-bar width.
        self.setFixedSize(QSize(max(1, round(size * _ASPECT)), size))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

    def sizeHint(self) -> QSize:                               # noqa: N802
        return QSize(max(1, round(self._size * _ASPECT)), self._size)

    def paintEvent(self, _event) -> None:                      # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        artwork = logo_pixmap()
        if artwork is not None:
            # No halo on the real artwork. The lockup carries its own hexagon
            # edge, so an added outline reads as a violet ring that is not in
            # the supplied image: it ships as drawn, or it is not the artwork
            # that was asked for. The painted fallback below still uses one,
            # because there the silhouette really would vanish into the chrome.
            _draw_scaled(painter, artwork,
                         QRectF(0, 0, self.width(), self.height()), halo=None)
            painter.end()
            return

        # The hexagon is taller than wide; inset so it fits the box.
        height = self.height() * 0.96
        width = height * _ASPECT
        box = QRectF((self.width() - width) / 2, (self.height() - height) / 2,
                     width, height)
        shape = hexagon(box)

        path = QPainterPath()
        path.addPolygon(shape)
        path.closeSubpath()

        painter.setClipPath(path)
        plate = plate_pixmap()
        if plate is not None:
            painter.drawPixmap(
                box.toRect(),
                plate.scaled(box.size().toSize(),
                             Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                             Qt.TransformationMode.SmoothTransformation))
        elif height >= _FIGURE_MIN_HEIGHT:
            _paint_noir_plate(painter, box)
        else:
            painter.fillRect(box, QColor("#0a0710"))
        painter.setClipping(False)

        painter.setPen(QPen(QColor(theme.ACCENT_DIM), max(1.0, height * 0.03)))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolygon(shape)

        _paint_ring(painter, box.center(), height * 0.20, height * 0.085)
        painter.end()


class MobWordmark(QWidget):
    """``The`` set above ``M O B``, the ``O`` a violet ring."""

    def __init__(self, height: int = 26, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._height = height
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setFixedWidth(self._measure())
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

    def _measure(self) -> int:
        cap = self._height * 0.62
        metrics = QFontMetricsF(mono_font(cap, QFont.Weight.Bold))
        radius = cap * 0.30
        gap = cap * 0.24
        total = (metrics.horizontalAdvance("M") + gap + 2 * radius + gap
                 + metrics.horizontalAdvance("B"))
        the = QFontMetricsF(
            mono_font(self._height * 0.30, spacing=self._height * 0.06)
        ).horizontalAdvance("The")
        return int(math.ceil(max(total, the) + 6))

    def paintEvent(self, _event) -> None:                      # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        the_size = self._height * 0.30
        painter.setFont(mono_font(the_size, spacing=self._height * 0.06))
        painter.setPen(QColor(theme.TEXT_PRIMARY))
        painter.drawText(QPointF(1.0, the_size + 1.0), "The")

        cap = self._height * 0.62
        _paint_mob(painter, QPointF(self.width() / 2, self._height * 0.66), cap,
                   theme.TEXT_PRIMARY)
        painter.end()


class MobLogo(QWidget):
    """The full lockup: hexagon, noir plate, ``The`` and ``M O B``."""

    def __init__(self, height: int = 190, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._height = height
        self.setFixedSize(self.sizeHint())
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

    def sizeHint(self) -> QSize:                               # noqa: N802
        # Take the aspect from the installed artwork so it is drawn at its own
        # proportions rather than forced into the fallback's.
        aspect = _ASPECT
        artwork = logo_pixmap()
        if artwork is not None and artwork.height() > 0:
            aspect = artwork.width() / artwork.height()
        return QSize(max(1, round(self._height * aspect)), self._height)

    def paintEvent(self, _event) -> None:                      # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        artwork = logo_pixmap()
        if artwork is not None:
            # No halo on the real artwork. The lockup carries its own hexagon
            # edge, so an added outline reads as a violet ring that is not in
            # the supplied image: it ships as drawn, or it is not the artwork
            # that was asked for. The painted fallback below still uses one,
            # because there the silhouette really would vanish into the chrome.
            _draw_scaled(painter, artwork,
                         QRectF(0, 0, self.width(), self.height()), halo=None)
            painter.end()
            return

        box = QRectF(0.5, 0.5, self.width() - 1.0, self.height() - 1.0)
        shape = hexagon(box)
        path = QPainterPath()
        path.addPolygon(shape)
        path.closeSubpath()

        painter.setClipPath(path)
        painter.fillRect(box, QColor("#000000"))

        left, top, right, bottom = _PLATE
        plate_rect = QRectF(box.x() + left * box.width(),
                            box.y() + top * box.height(),
                            (right - left) * box.width(),
                            (bottom - top) * box.height())
        plate = plate_pixmap()
        if plate is not None:
            painter.drawPixmap(
                plate_rect.toRect(),
                plate.scaled(plate_rect.size().toSize(),
                             Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                             Qt.TransformationMode.SmoothTransformation))
        else:
            _paint_noir_plate(painter, plate_rect)

        the_size = box.height() * 0.056
        painter.setFont(mono_font(the_size, spacing=box.height() * 0.024))
        painter.setPen(QColor("#ffffff"))
        painter.drawText(QPointF(box.x() + box.width() * 0.20,
                                 box.y() + box.height() * 0.29), "The")

        _paint_mob(painter,
                   QPointF(box.center().x(), box.y() + box.height() * 0.46),
                   box.height() * 0.17)

        painter.setClipping(False)
        painter.setPen(QPen(QColor(theme.ACCENT_DIM), max(1.2, box.height() * 0.012)))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolygon(shape)
        painter.end()
