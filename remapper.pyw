import ctypes
from ctypes import wintypes
import sys
import os
import glob
import json
import math
import threading
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QFont, QPolygonF, QPen
from PyQt6.QtCore import Qt, QTimer, QPointF

# ── Settings ───────────────────────────────────────────────────────────────────
SETTINGS_DIR  = os.path.join(os.environ["APPDATA"], "cli-tools")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "remapper.json")

_MODE_MIGRATE = {"normal": "ll_hook", "admin": "ll_hook", "interception": "kernel"}

def load_settings():
    try:
        with open(SETTINGS_FILE, "r") as f:
            data = json.load(f)
        data["mode"] = _MODE_MIGRATE.get(data.get("mode"), data.get("mode", "synthetic"))
        return data
    except Exception:
        return {"mode": "synthetic", "layout": None}

def save_settings(mode, layout):
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump({"mode": mode, "layout": layout}, f, indent=2)

# ── Layout loading ─────────────────────────────────────────────────────────────
# 47-key baseline: number row (1234567890-=), top row (qwertyuiop[]\),
# home row (asdfghjkl;'), bottom row (zxcvbnm,./)
QWERTY_BASELINE = "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"

CHAR_TO_VK = {
    '1':0x31,'2':0x32,'3':0x33,'4':0x34,'5':0x35,
    '6':0x36,'7':0x37,'8':0x38,'9':0x39,'0':0x30,
    '-':0xBD,'=':0xBB,
    'q':0x51,'w':0x57,'e':0x45,'r':0x52,'t':0x54,'y':0x59,'u':0x55,'i':0x49,'o':0x4F,'p':0x50,
    '[':0xDB,']':0xDD,'\\':0xDC,
    'a':0x41,'s':0x53,'d':0x44,'f':0x46,'g':0x47,'h':0x48,'j':0x4A,'k':0x4B,'l':0x4C,';':0xBA,
    "'":0xDE,
    'z':0x5A,'x':0x58,'c':0x43,'v':0x56,'b':0x42,'n':0x4E,'m':0x4D,
    ',':0xBC,'.':0xBE,'/':0xBF,
}


def build_vk_map(layout_string):
    if len(layout_string) != len(QWERTY_BASELINE):
        raise ValueError(
            f"Layout string length {len(layout_string)} doesn't match baseline "
            f"({len(QWERTY_BASELINE)}). "
            f"Expected 47 chars covering: 1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"
        )
    mapping = {}
    for qwerty_char, layout_char in zip(QWERTY_BASELINE, layout_string):
        from_vk = CHAR_TO_VK[qwerty_char]
        to_vk   = CHAR_TO_VK.get(layout_char)
        if to_vk is None:
            raise ValueError(f"Unknown character '{layout_char}' in layout string")
        if from_vk != to_vk:
            mapping[from_vk] = to_vk
    return mapping

def scan_layouts(directory):
    layouts = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.layout"))):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        layouts[name] = build_vk_map(line)
                        break
        except Exception as e:
            print(f"Warning: could not load '{path}': {e}")
    return layouts

# ── SendInput remapper (capture via LL hook, inject via SendInput) ────────────
KEYEVENTF_KEYUP    = 0x0002
KEYEVENTF_SCANCODE = 0x0008

class INPUT_KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk",         wintypes.WORD),
        ("wScan",       wintypes.WORD),
        ("dwFlags",     wintypes.DWORD),
        ("time",        wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]

class _INPUT_UNION(ctypes.Union):
    _fields_ = [("ki", INPUT_KEYBDINPUT), ("_pad", ctypes.c_byte * 32)]

class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("_u", _INPUT_UNION)]

INPUT_KEYBOARD = 1

def _send_key(vk: int, key_up: bool):
    inp = INPUT()
    inp.type          = INPUT_KEYBOARD
    inp._u.ki.wVk     = vk
    inp._u.ki.dwFlags = KEYEVENTF_KEYUP if key_up else 0
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


# ── WM_LL_KEYBOARD hook (ctypes) ──────────────────────────────────────────────
WH_KEYBOARD_LL = 13
WM_KEYDOWN     = 0x0100
WM_KEYUP       = 0x0101
WM_SYSKEYDOWN  = 0x0104
WM_SYSKEYUP    = 0x0105
LLKHF_INJECTED = 0x00000010

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode",      wintypes.DWORD),
        ("scanCode",    wintypes.DWORD),
        ("flags",       wintypes.DWORD),
        ("time",        wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]

LRESULT   = ctypes.c_longlong
PHOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
user32    = ctypes.windll.user32
kernel32  = ctypes.windll.kernel32
user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.SendInput.restype  = wintypes.UINT
user32.CallNextHookEx.argtypes  = [wintypes.HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
user32.CallNextHookEx.restype   = LRESULT
user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
user32.UnhookWindowsHookEx.restype  = wintypes.BOOL

_ll_state = {"hook_id": None, "vk_map": {}, "enabled": False, "use_sendinput": False}

def _ll_callback(nCode, wParam, lParam):
    if nCode >= 0 and _ll_state["enabled"]:
        kb = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        if not (kb.flags & LLKHF_INJECTED):
            mapped = _ll_state["vk_map"].get(kb.vkCode)
            if mapped is not None:
                key_up = wParam in (WM_KEYUP, WM_SYSKEYUP)
                if _ll_state.get("use_sendinput"):
                    _send_key(mapped, key_up)
                else:
                    flags = KEYEVENTF_KEYUP if key_up else 0
                    user32.keybd_event(mapped, 0, flags, 0)
                return 1
    return user32.CallNextHookEx(None, nCode, wParam, lParam)

_ll_proc = PHOOKPROC(_ll_callback)

def _install_ll_hook():
    if _ll_state["hook_id"] is None:
        hid = user32.SetWindowsHookExW(WH_KEYBOARD_LL, _ll_proc, 0, 0)
        if not hid:
            print(f"LL hook failed: {kernel32.GetLastError()}")
        _ll_state["hook_id"] = hid

def _remove_ll_hook():
    if _ll_state["hook_id"]:
        user32.UnhookWindowsHookEx(_ll_state["hook_id"])
        _ll_state["hook_id"] = None


# ── Interception (kernel driver) ──────────────────────────────────────────────
INTERCEPTION_DLL = r"C:\Users\I\Desktop\Books and stuff\Tools\interception_x64.dll"

SCAN_TO_CHAR = {
    2:'1', 3:'2', 4:'3', 5:'4', 6:'5', 7:'6', 8:'7', 9:'8', 10:'9', 11:'0',
    12:'-', 13:'=',
    16:'q',17:'w',18:'e',19:'r',20:'t',21:'y',22:'u',23:'i',24:'o',25:'p',
    26:'[',27:']',43:'\\',
    30:'a',31:'s',32:'d',33:'f',34:'g',35:'h',36:'j',37:'k',38:'l',39:';',
    40:"'",
    44:'z',45:'x',46:'c',47:'v',48:'b',49:'n',50:'m',
    51:',',52:'.',53:'/',
}
CHAR_TO_SCAN = {v: k for k, v in SCAN_TO_CHAR.items()}

class KeyStroke(ctypes.Structure):
    _fields_ = [
        ("code",        ctypes.c_ushort),
        ("state",       ctypes.c_ushort),
        ("information", ctypes.c_ulong),
    ]

_ilib = None

def _load_interception():
    global _ilib
    if _ilib is not None:
        return _ilib
    lib = ctypes.WinDLL(INTERCEPTION_DLL)
    lib.interception_create_context.restype  = ctypes.c_void_p
    lib.interception_create_context.argtypes = []
    lib.interception_destroy_context.restype  = None
    lib.interception_destroy_context.argtypes = [ctypes.c_void_p]
    lib.interception_set_filter.restype  = None
    lib.interception_set_filter.argtypes = [
        ctypes.c_void_p,
        ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int),
        ctypes.c_ushort,
    ]
    lib.interception_wait_with_timeout.restype  = ctypes.c_int
    lib.interception_wait_with_timeout.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    lib.interception_receive.restype  = ctypes.c_int
    lib.interception_receive.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    lib.interception_send.restype  = ctypes.c_int
    lib.interception_send.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    _ilib = lib
    return lib


# ── Theme ──────────────────────────────────────────────────────────────────────
DARK   = "#0d1f2d"
BORDER = "#1e3a47"

MODE_META = {
    "synthetic":    ("SendInput   (modern API)",  "#00c9a7"),
    "ll_hook":      ("WM_LL_HOOK  (keybd_event)", "#c9a700"),
    "kernel":       ("Kernel      (interception)","#c9007a"),
}

MENU_STYLE = (
    f"QMenu{{background:{DARK};border:1px solid {BORDER};color:#d8eaed;"
    f"font-family:'Segoe UI',sans-serif;font-size:13px;padding:4px;}}"
    f"QMenu::item{{padding:6px 22px;border-radius:4px;}}"
    f"QMenu::item:selected{{background:#005f73;color:#00c9a7;}}"
    f"QMenu::separator{{background:{BORDER};height:1px;margin:4px 0;}}"
)

def make_icon(enabled: bool, mode: str = "synthetic", label: str = "??") -> QIcon:
    SIZE = 256
    pix  = QPixmap(SIZE, SIZE)
    pix.fill(QColor(0, 0, 0, 0))
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    cx, cy  = SIZE / 2, SIZE / 2
    r_outer = SIZE / 2 - 10
    r_inner = SIZE / 2 - 4
    angles  = [math.radians(-90 + 60 * i) for i in range(6)]
    poly        = QPolygonF([QPointF(cx + r_outer * math.cos(a), cy + r_outer * math.sin(a)) for a in angles])
    border_poly = QPolygonF([QPointF(cx + r_inner * math.cos(a), cy + r_inner * math.sin(a)) for a in angles])
    accent = QColor(MODE_META[mode][1])
    p.setBrush(accent if enabled else QColor("#1a2e38"))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawPolygon(poly)
    pen = QPen(QColor(DARK) if enabled else accent, 10)
    pen.setJoinStyle(Qt.PenJoinStyle.MiterJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPolygon(border_poly)
    p.setPen(QColor(DARK if enabled else accent))
    p.setFont(QFont("Segoe UI", 80, QFont.Weight.Bold))
    p.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, label[:2].upper())
    p.end()
    return QIcon(pix)


# ── Tray ───────────────────────────────────────────────────────────────────────
class RemapperTray(QSystemTrayIcon):
    def __init__(self, layouts: dict):
        super().__init__()
        self.layouts       = layouts
        self.active_layout = None
        self.active_mode   = "synthetic"

        # Interception backend
        self._i_ctx   = None
        self._i_pred  = None
        self._i_vk_map: dict = {}
        self.i_timer  = QTimer()
        self.i_timer.setInterval(1)
        self.i_timer.timeout.connect(self._interception_tick)

        self._build_menu()
        self.setIcon(make_icon(False, "synthetic", "off"))
        self.setToolTip("Remapper — off")
        self.activated.connect(self._on_activated)

        # LL hook is always installed; enabled flag gates remapping
        _install_ll_hook()

        self.show()

        saved = load_settings()
        if saved.get("layout") and saved["layout"] in layouts:
            self._set_mode(saved.get("mode", "synthetic"))
            self._activate_layout(saved["layout"])
        elif saved.get("mode"):
            self._set_mode(saved["mode"])

    # ── Menu ──────────────────────────────────────────────────────────────────
    def _build_menu(self):
        self.menu = QMenu()
        self.menu.setStyleSheet(MENU_STYLE)

        self.menu.addAction("── Mode ──").setEnabled(False)
        self.mode_actions = {}
        for mode, (label, _) in MODE_META.items():
            a = self.menu.addAction(f"○  {label}")
            a.triggered.connect(lambda checked, m=mode: self._set_mode(m))
            self.mode_actions[mode] = a
        self.menu.addSeparator()

        self.menu.addAction("── Layout ──").setEnabled(False)
        self.qwerty_action = self.menu.addAction("◉  QWERTY (off)")
        self.qwerty_action.triggered.connect(lambda: self._activate_layout(None))
        self.menu.addSeparator()

        self.layout_actions = {}
        for name in self.layouts:
            a = self.menu.addAction(f"○  {name}")
            a.triggered.connect(lambda checked, n=name: self._activate_layout(n))
            self.layout_actions[name] = a

        if not self.layouts:
            na = self.menu.addAction("(no .layout files found)")
            na.setEnabled(False)

        self.menu.addSeparator()
        self.menu.addAction("↻  Reload layouts").triggered.connect(self._reload_layouts)
        self.menu.addSeparator()
        self.menu.addAction("✕  Quit").triggered.connect(self._quit)

    # ── Mode switching ────────────────────────────────────────────────────────
    def _teardown_all(self):
        """Stop every backend cleanly."""
        _ll_state["enabled"]       = False
        _ll_state["use_sendinput"] = False
        self._stop_interception()

    def _set_mode(self, mode: str):
        self._teardown_all()
        self.active_mode = mode
        vk_map = self.layouts.get(self.active_layout, {}) if self.active_layout else {}

        if mode == "synthetic":
            _ll_state["vk_map"]       = vk_map
            _ll_state["enabled"]      = bool(vk_map)
            _ll_state["use_sendinput"] = True

        elif mode == "ll_hook":
            _ll_state["vk_map"]        = vk_map
            _ll_state["enabled"]       = bool(vk_map)
            _ll_state["use_sendinput"] = False

        elif mode == "kernel":
            if vk_map:
                self._start_interception(vk_map)

        self._refresh_icon()
        self._refresh_mode_menu()
        save_settings(self.active_mode, self.active_layout)

    # ── Layout switching ──────────────────────────────────────────────────────
    def _activate_layout(self, name):
        self.active_layout = name
        vk_map = self.layouts.get(name, {}) if name else {}

        if self.active_mode == "synthetic":
            _ll_state["vk_map"]        = vk_map
            _ll_state["enabled"]       = bool(vk_map)
            _ll_state["use_sendinput"] = True

        elif self.active_mode == "ll_hook":
            _ll_state["vk_map"]  = vk_map
            _ll_state["enabled"] = bool(vk_map)

        elif self.active_mode == "kernel":
            self._stop_interception()
            if vk_map:
                self._start_interception(vk_map)

        # Update menu bullets
        self.qwerty_action.setText("◉  QWERTY (off)" if name is None else "○  QWERTY (off)")
        for n, a in self.layout_actions.items():
            a.setText(f"{'◉' if n == name else '○'}  {n}")

        self._refresh_icon()
        save_settings(self.active_mode, self.active_layout)
        self.showMessage(
            "Remapper",
            f"{MODE_META[self.active_mode][0].strip()} · {name or 'QWERTY (off)'}",
            QSystemTrayIcon.MessageIcon.NoIcon, 2000,
        )

    # ── Interception helpers ──────────────────────────────────────────────────
    def _start_interception(self, vk_map: dict):
        try:
            lib = _load_interception()
        except Exception as e:
            self.showMessage("Remapper", f"Interception DLL not found:\n{e}",
                             QSystemTrayIcon.MessageIcon.Critical, 4000)
            return
        self._i_ctx    = lib.interception_create_context()
        self._i_vk_map = vk_map
        PRED           = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
        self._i_pred   = PRED(lambda d: 1 if 1 <= d <= 10 else 0)
        lib.interception_set_filter(self._i_ctx, self._i_pred, 0xFFFF)
        self.i_timer.start()

    def _stop_interception(self):
        self.i_timer.stop()
        if self._i_ctx:
            _load_interception().interception_destroy_context(self._i_ctx)
            self._i_ctx = None

    def _interception_tick(self):
        lib    = _load_interception()
        device = lib.interception_wait_with_timeout(self._i_ctx, 0)
        if device == 0:
            return
        stroke = KeyStroke()
        n = lib.interception_receive(self._i_ctx, device, ctypes.byref(stroke), 1)
        if n > 0:
            char    = SCAN_TO_CHAR.get(stroke.code)
            from_vk = CHAR_TO_VK.get(char) if char else None
            to_vk   = self._i_vk_map.get(from_vk) if from_vk else None
            if to_vk:
                to_char  = next((c for c, v in CHAR_TO_VK.items() if v == to_vk), None)
                to_scan  = CHAR_TO_SCAN.get(to_char, stroke.code)
                stroke.code = to_scan
            lib.interception_send(self._i_ctx, device, ctypes.byref(stroke), 1)

    # ── UI helpers ────────────────────────────────────────────────────────────
    def _refresh_icon(self):
        enabled = bool(self.active_layout)
        label   = (self.active_layout or "off")[:2].upper()
        self.setIcon(make_icon(enabled, self.active_mode, label))
        self.setToolTip(
            f"Remapper — {MODE_META[self.active_mode][0].strip()}\n"
            f"Layout: {self.active_layout or 'QWERTY (off)'}"
        )

    def _refresh_mode_menu(self):
        for m, a in self.mode_actions.items():
            label = MODE_META[m][0]
            a.setText(f"{'◉' if m == self.active_mode else '○'}  {label}")

    def _is_elevated(self):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _reload_layouts(self):
        script_dir     = os.path.dirname(os.path.abspath(__file__))
        self.layouts   = scan_layouts(script_dir)
        self.layout_actions = {}
        self.menu.clear()
        self._build_menu()
        if self.active_layout and self.active_layout not in self.layouts:
            self._activate_layout(None)
        elif self.active_layout:
            self._activate_layout(self.active_layout)
        self.showMessage("Remapper", f"Reloaded — {len(self.layouts)} layout(s)",
                         QSystemTrayIcon.MessageIcon.NoIcon, 2000)

    def _on_activated(self, reason):
        AR = QSystemTrayIcon.ActivationReason
        if reason == AR.Trigger:
            names = [None] + list(self.layouts.keys())
            cur   = self.active_layout
            idx   = names.index(cur) if cur in names else 0
            self._activate_layout(names[(idx + 1) % len(names)])
        elif reason == AR.MiddleClick:
            self.menu.popup(self.geometry().topLeft())
        elif reason == AR.Context:
            self._quit()

    def _quit(self):
        self._teardown_all()
        _remove_ll_hook()
        QApplication.quit()


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    layouts    = scan_layouts(script_dir)
    print(f"Loaded {len(layouts)} layout(s): {list(layouts.keys())}")
    tray = RemapperTray(layouts)
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
