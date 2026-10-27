"""Java syntax highlighting for the decompiled-code browser.

The build plan called for Monaco, which needs a web view; this is the Qt-native
equivalent and keeps the "no bundled JavaScript in a security tool" rule.
``QSyntaxHighlighter`` re-highlights only the blocks that changed, so it stays
responsive on the large files jadx produces.

Deliberately lexical, not semantic: it colours tokens, it does not parse Java.
Decompiled output is frequently *not* valid Java, jadx emits partial method
bodies under ``--show-bad-code``, and a real parser would give up on exactly
the files a tester most wants to read.
"""
from __future__ import annotations

import re

from PyQt6.QtCore import QRegularExpression, Qt
from PyQt6.QtGui import (QColor, QFont, QSyntaxHighlighter, QTextCharFormat,
                         QTextDocument)

from ...model.enums import Severity
from .. import theme

_KEYWORDS = (
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char",
    "class", "const", "continue", "default", "do", "double", "else", "enum",
    "extends", "final", "finally", "float", "for", "goto", "if", "implements",
    "import", "instanceof", "int", "interface", "long", "native", "new",
    "package", "private", "protected", "public", "return", "short", "static",
    "strictfp", "super", "switch", "synchronized", "this", "throw", "throws",
    "transient", "try", "void", "volatile", "while", "var", "record", "yield",
    "sealed", "permits",
)
_LITERALS = ("true", "false", "null")

#: Android/Java APIs worth catching the eye in a security review. Highlighting
#: is not detection: semgrep does that, but a reviewer scrolling a file should
#: not have to hunt for the crypto call.
_NOTABLE = (
    "Cipher", "MessageDigest", "SecretKeySpec", "IvParameterSpec", "KeyStore",
    "SecureRandom", "Random", "TrustManager", "X509TrustManager", "HostnameVerifier",
    "SSLContext", "SSLSocketFactory", "WebView", "addJavascriptInterface",
    "loadUrl", "evaluateJavascript", "setJavaScriptEnabled",
    "SharedPreferences", "openFileOutput", "getExternalStorageDirectory",
    "SQLiteDatabase", "rawQuery", "execSQL", "Runtime", "exec", "ProcessBuilder",
    "getInstalledPackages", "PendingIntent", "sendBroadcast", "startActivity",
)


def _format(color: str, *, bold: bool = False, italic: bool = False) -> QTextCharFormat:
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(color))
    if bold:
        fmt.setFontWeight(QFont.Weight.Bold)
    if italic:
        fmt.setFontItalic(True)
    return fmt


class JavaHighlighter(QSyntaxHighlighter):
    """Lexical highlighting for decompiled Java."""

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)

        keyword = _format(theme.SYNTAX["keyword"], bold=True)
        literal = _format(theme.SYNTAX["literal"])
        string = _format(theme.SYNTAX["string"])
        number = _format(theme.SYNTAX["number"])
        comment = _format(theme.SYNTAX["comment"], italic=True)
        annotation = _format(theme.SYNTAX["annotation"])
        type_name = _format(theme.SYNTAX["type"])
        notable = _format(theme.severity_color(Severity.HIGH), bold=True)

        self._rules: list[tuple[QRegularExpression, QTextCharFormat]] = []

        def rule(pattern: str, fmt: QTextCharFormat) -> None:
            self._rules.append((QRegularExpression(pattern), fmt))

        rule(r"\b(?:" + "|".join(_KEYWORDS) + r")\b", keyword)
        rule(r"\b(?:" + "|".join(_LITERALS) + r")\b", literal)
        # A capitalised identifier is a type, near enough, in decompiled output.
        rule(r"\b[A-Z][A-Za-z0-9_]*\b", type_name)
        rule(r"\b(?:" + "|".join(map(re.escape, _NOTABLE)) + r")\b", notable)
        rule(r"@[A-Za-z_][A-Za-z0-9_.]*", annotation)
        rule(r"\b0[xX][0-9a-fA-F_]+[LlFfDd]?\b", number)
        rule(r"\b\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?[LlFfDd]?\b", number)
        # Strings and chars last, so they win over anything matched inside them.
        rule(r'"(?:[^"\\\n]|\\.)*"', string)
        rule(r"'(?:[^'\\\n]|\\.)*'", string)
        rule(r"//[^\n]*", comment)

        self._comment_format = comment
        self._block_start = QRegularExpression(r"/\*")
        self._block_end = QRegularExpression(r"\*/")

    def highlightBlock(self, text: str) -> None:                # noqa: N802
        for pattern, fmt in self._rules:
            match = pattern.globalMatch(text)
            while match.hasNext():
                found = match.next()
                self.setFormat(found.capturedStart(), found.capturedLength(), fmt)

        self._highlight_block_comments(text)

    def _highlight_block_comments(self, text: str) -> None:
        """``/* ... */`` spans blocks, so it needs the multi-block state."""
        self.setCurrentBlockState(0)
        start = 0
        if self.previousBlockState() != 1:
            found = self._block_start.match(text)
            start = found.capturedStart() if found.hasMatch() else -1

        while start >= 0:
            end_match = self._block_end.match(text, start)
            if end_match.hasMatch():
                length = end_match.capturedEnd() - start
            else:
                self.setCurrentBlockState(1)
                length = len(text) - start
            self.setFormat(start, length, self._comment_format)

            next_match = self._block_start.match(text, start + length)
            start = next_match.capturedStart() if next_match.hasMatch() else -1


def source_font(point_size: int = 10) -> QFont:
    """A monospace face for the code viewer."""
    font = QFont()
    font.setFamilies(["JetBrains Mono", "Cascadia Mono", "Consolas",
                      "DejaVu Sans Mono", "Courier New"])
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFixedPitch(True)
    font.setPointSize(point_size)
    return font
