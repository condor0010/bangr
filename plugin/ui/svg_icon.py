# svg_icon.py
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QImage, QPainter
import os

def render_svg_icon(path_icon):
    renderer = QSvgRenderer(path_icon)
    icon = QImage(56, 56, QImage.Format_ARGB32)
    icon.fill(0xaaA08080)  # Fallback color
    painter = QPainter(icon)
    renderer.render(painter)
    painter.end()
    return icon

