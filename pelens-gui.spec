# PyInstaller spec of the GUI (pelens-gui.exe): only the Qt parts PELens uses, to keep the exe small.
# Used by build_exe.bat:  python -m PyInstaller --noconfirm pelens-gui.spec
import re

from PyInstaller.utils.hooks import collect_all, collect_data_files

datas = collect_data_files("pelens") + collect_data_files("mscerts")
binaries = []
hiddenimports = ["dnfile", "yara"]
d, b, h = collect_all("capstone")
datas += d
binaries += b
hiddenimports += h

# Python modules never used by PELens (pulled in by optional imports of other packages when installed)
EXCLUDES = [
    "tkinter", "matplotlib", "numpy", "PIL", "scipy", "pandas", "IPython", "pytest",
    # OpenSSL (ssl/_hashlib: hashlib falls back to the built-in md5/sha*) and other modules PELens never loads
    "ssl", "_ssl", "_hashlib", "pygments", "markdown_it", "chardet", "asyncio", "multiprocessing", "unittest",
    "pydoc", "pydoc_data", "xmlrpc", "sqlite3", "_sqlite3", "cffi", "_cffi_backend", "lib2to3", "setuptools", "pip",
    "distutils", "cryptography",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.QtQuickControls2", "PySide6.QtPdf",
    "PySide6.QtPdfWidgets", "PySide6.QtNetwork", "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtSql",
    "PySide6.QtTest", "PySide6.QtDBus", "PySide6.QtXml", "PySide6.QtConcurrent", "PySide6.QtPrintSupport",
    "PySide6.QtVirtualKeyboard", "PySide6.QtMultimedia", "PySide6.QtWebEngineCore", "PySide6.QtHelp",
    "PySide6.QtDesigner", "PySide6.QtUiTools", "PySide6.QtSvgWidgets", "PySide6.QtStateMachine",
]

# Qt files that PELens does not need: software OpenGL and Direct3D compiler (only for Qt Quick/OpenGL),
# QML/Quick/PDF/network libraries, translations, plugins other than the platform, style and a few image formats
DROP = re.compile(
    r"(opengl32sw|d3dcompiler_\d+|Qt6(Quick|Qml|Pdf|Network|OpenGL|VirtualKeyboard|Wayland|Multimedia|Sql|Test|"
    r"Designer|Help|Xml|Concurrent|PrintSupport|StateMachine|SvgWidgets)\w*)\.(dll|so[.\d]*|pyd)$"
    r"|[\\/]translations[\\/]",
    re.I)
PLUGIN = re.compile(r"[\\/]plugins[\\/]([^\\/]+)[\\/]([^\\/]+)$", re.I)
KEEP_PLUGINS = {
    "platforms": re.compile(r"^(lib)?q(windows|xcb|offscreen|cocoa)", re.I),
    "styles": re.compile(r".", re.I),
    "imageformats": re.compile(r"^(lib)?q(ico|jpeg|gif)", re.I),    # PNG and BMP are built into Qt
}


def keep(dest: str) -> bool:
    if DROP.search(dest):
        return False
    m = PLUGIN.search(dest)
    if m:
        rule = KEEP_PLUGINS.get(m.group(1).lower())
        return bool(rule and rule.search(m.group(2)))
    return True


a = Analysis(["run_pelens_gui.py"], pathex=[], binaries=binaries, datas=datas, hiddenimports=hiddenimports,
             excludes=EXCLUDES, noarchive=False)
a.binaries = [x for x in a.binaries if keep(x[0])]
a.datas = [x for x in a.datas if keep(x[0])]
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="pelens-gui", icon="assets/pelens.ico",
          console=False, upx=False, strip=False, debug=False, runtime_tmpdir=None)
