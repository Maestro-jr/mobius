"""Native Windows frame behaviour for the frameless shell.

A frameless Qt window loses what Windows users expect: Aero Snap (drag to an
edge, Win + arrow keys), the Windows 11 snap layouts menu on the maximize
button, resizing from the edges, and the drop shadow. This module puts the
native frame styles back and then hides the frame itself by answering
WM_NCCALCSIZE, so the custom title bar stays while the system treats the window
as a normal resizable, snappable one.

Copied from the desktop UI kit (reference/winframe.py). Everything here is a
no-op on other platforms.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from PyQt6.QtCore import QPoint
from PyQt6.QtWidgets import QAbstractButton

IS_WINDOWS = sys.platform == "win32"

WM_NCCALCSIZE = 0x0083
WM_NCHITTEST = 0x0084
WM_NCMOUSEMOVE = 0x00A0
WM_NCLBUTTONDOWN = 0x00A1
WM_NCLBUTTONUP = 0x00A2
WM_NCLBUTTONDBLCLK = 0x00A3
WM_NCMOUSELEAVE = 0x02A2

HTCLIENT, HTCAPTION, HTMAXBUTTON = 1, 2, 9
HTLEFT, HTRIGHT, HTTOP, HTTOPLEFT, HTTOPRIGHT = 10, 11, 12, 13, 14
HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT = 15, 16, 17

GWL_STYLE = -16
WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
WS_SYSMENU = 0x00080000

SWP_NOSIZE, SWP_NOMOVE, SWP_NOZORDER = 0x0001, 0x0002, 0x0004
SWP_NOACTIVATE, SWP_FRAMECHANGED = 0x0010, 0x0020

SM_CXSIZEFRAME, SM_CYSIZEFRAME, SM_CXPADDEDBORDER = 32, 33, 92

RESIZE_BORDER = 6          # logical pixels of grab area at each edge


class _MARGINS(ctypes.Structure):
    _fields_ = [("left", ctypes.c_int), ("right", ctypes.c_int),
                ("top", ctypes.c_int), ("bottom", ctypes.c_int)]


def _metric(index: int, hwnd: int) -> int:
    """System metric at the window's own DPI (per-monitor aware), with a
    fallback for older Windows builds."""
    user32 = ctypes.windll.user32
    try:
        dpi = user32.GetDpiForWindow(wintypes.HWND(int(hwnd)))
        return user32.GetSystemMetricsForDpi(index, dpi)
    except AttributeError:
        return user32.GetSystemMetrics(index)


class WindowsFrame:
    """Attach to a frameless top-level window. Call install() once the window
    has a native handle, and route nativeEvent through handle()."""

    def __init__(self, window, titlebar_height: int, max_button=None,
                 resizable: bool = True, maximizable: bool = True) -> None:
        """`resizable` gives edge and corner resizing; `maximizable` adds the
        min/max boxes so Aero Snap and Win + arrow work. A message box wants
        neither (it still gets the shadow and a draggable title bar)."""
        self._win = window
        self._title_h = titlebar_height
        self._max_btn = max_button
        self._resizable = resizable
        self._maximizable = maximizable
        # Messages arrive while Qt is still creating the native window; touching
        # the half-built window then crashes. Stay passive until install() ends.
        self._active = False

    # ---- setup ----
    def install(self) -> None:
        if not IS_WINDOWS:
            return
        user32 = ctypes.windll.user32
        hwnd = wintypes.HWND(int(self._win.winId()))
        style = user32.GetWindowLongW(hwnd, GWL_STYLE)
        style |= WS_CAPTION | WS_THICKFRAME | WS_SYSMENU
        if self._maximizable:
            style |= WS_MINIMIZEBOX | WS_MAXIMIZEBOX
        user32.SetWindowLongW(hwnd, GWL_STYLE, style)
        try:
            margins = _MARGINS(1, 1, 1, 1)   # lets DWM draw the drop shadow
            ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(
                hwnd, ctypes.byref(margins))
        except (AttributeError, OSError):
            pass
        self._active = True
        user32.SetWindowPos(hwnd, None, 0, 0, 0, 0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                            SWP_NOACTIVATE | SWP_FRAMECHANGED)

    # ---- messages ----
    def handle(self, message) -> tuple:
        """Return (handled, result) for a windows_generic_MSG."""
        if not self._active:
            return False, 0
        msg = wintypes.MSG.from_address(int(message))
        m = msg.message

        if m == WM_NCCALCSIZE:
            if msg.wParam and ctypes.windll.user32.IsZoomed(wintypes.HWND(msg.hWnd)):
                # A maximized window overhangs the monitor by the frame width;
                # pull the client area back in so nothing is cut off.
                hwnd = int(msg.hWnd)
                fx = _metric(SM_CXSIZEFRAME, hwnd) + _metric(SM_CXPADDEDBORDER, hwnd)
                fy = _metric(SM_CYSIZEFRAME, hwnd) + _metric(SM_CXPADDEDBORDER, hwnd)
                rect = wintypes.RECT.from_address(msg.lParam)
                rect.left += fx
                rect.top += fy
                rect.right -= fx
                rect.bottom -= fy
            return True, 0

        if m == WM_NCHITTEST:
            return True, self._hit_test(msg)

        if m == WM_NCMOUSEMOVE:
            self._set_max_hot(msg.wParam == HTMAXBUTTON)
            return False, 0

        if m == WM_NCMOUSELEAVE:
            self._set_max_hot(False)
            return False, 0

        if msg.wParam == HTMAXBUTTON:
            if m in (WM_NCLBUTTONDOWN, WM_NCLBUTTONDBLCLK):
                return True, 0
            if m == WM_NCLBUTTONUP:
                self._toggle_max()
                return True, 0

        return False, 0

    def hit_test_local(self, lx: float, ly: float) -> int:
        """Hit-test a point in logical window coordinates."""
        win = self._win
        w, h = win.width(), win.height()
        child = win.childAt(QPoint(int(lx), int(ly)))
        if self._resizable and not win.isMaximized():
            b = RESIZE_BORDER
            left, right = lx < b, lx >= w - b
            # The window controls run flush to the top edge, so over them the
            # button wins the top band (a click there closes, it does not
            # resize). The right edge still resizes.
            top = ly < b and not self._is_window_control(child)
            bottom = ly >= h - b
            if top and left:
                return HTTOPLEFT
            if top and right:
                return HTTOPRIGHT
            if bottom and left:
                return HTBOTTOMLEFT
            if bottom and right:
                return HTBOTTOMRIGHT
            if left:
                return HTLEFT
            if right:
                return HTRIGHT
            if top:
                return HTTOP
            if bottom:
                return HTBOTTOM

        node = child
        while node is not None and node is not win:
            if self._max_btn is not None and node is self._max_btn:
                return HTMAXBUTTON
            if isinstance(node, QAbstractButton):
                return HTCLIENT
            node = node.parentWidget()
        if ly < self._title_h:
            return HTCAPTION
        return HTCLIENT

    def _is_window_control(self, widget) -> bool:
        node = widget
        while node is not None and node is not self._win:
            if node.objectName() in ("winBtn", "winClose"):
                return True
            node = node.parentWidget()
        return False

    def _hit_test(self, msg) -> int:
        rect = wintypes.RECT()
        ctypes.windll.user32.GetWindowRect(wintypes.HWND(msg.hWnd), ctypes.byref(rect))
        x = ctypes.c_short(msg.lParam & 0xFFFF).value
        y = ctypes.c_short((msg.lParam >> 16) & 0xFFFF).value
        dpr = self._win.devicePixelRatioF() or 1.0
        return self.hit_test_local((x - rect.left) / dpr, (y - rect.top) / dpr)

    def _set_max_hot(self, hot: bool) -> None:
        if self._max_btn is not None and hasattr(self._max_btn, "set_hot"):
            self._max_btn.set_hot(hot)

    def _toggle_max(self) -> None:
        if self._win.isMaximized():
            self._win.showNormal()
        else:
            self._win.showMaximized()
