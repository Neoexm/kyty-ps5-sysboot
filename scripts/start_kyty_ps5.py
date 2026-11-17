import argparse
import configparser
import ctypes
import hashlib
import json
import msvcrt
import os
import secrets
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "scripts/boot_profile.json"
CONFIG = ROOT / "kyty.ini"
CACHE = ROOT / "runtime/cache/immutable_metadata"
PSNOW_SELF_SHA256 = "a6826c981e0227552f1cd08c59dd2e9995b69e9b10b568138a08dcc28a509a18"
PSNOW_OBSERVATION_SHA256 = "3a899ca1e3334410138c2986a9085cc032ca202bbc78cf47a1edf82e1ab9f65c"
ERROR_OBJECT_LIMIT = 4 * 1024 * 1024


class Boot:
    def __init__(self):
        if not CONFIG.exists():
            raise FileNotFoundError(f"{CONFIG} not found; copy kyty.example.ini to kyty.ini and fill it in")
        self.config = configparser.ConfigParser()
        self.config.read_dict({
            "paths": {"firmware": "firmware", "evidence": "evidence", "emulator": "_Build/vsh/kyty_emulator.exe"},
            "provider": {"token_file": "", "port": "9038", "timeout_ms": "300000"},
            "boot": {"readbacks": "no", "show_services": "no"},
        })
        self.config.read(CONFIG, encoding="utf-8")
        self.exe = self.path("paths", "emulator")
        self.firmware_root = self.path("paths", "firmware").resolve()
        self.runs = self.path("paths", "evidence") / "runs/manual_boots"
        self.token_file = self.path("provider", "token_file") if self.config.get("provider", "token_file").strip() else None
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.firmware_paths = []
        self.environment = {key: self.expand(value) for key, value in profile["environment"].items()}
        self.game = Path(self.expand(profile["game"]))
        self.sysroot = Path(self.expand(profile["sysroot"]))
        self.psnow = Path(self.environment["KYTY_PS5_AUTHORIZATION_OBSERVATION_" + PSNOW_SELF_SHA256])

    def path(self, section, key):
        value = Path(os.path.expandvars(self.config.get(section, key).strip()))
        return value if value.is_absolute() else ROOT / value

    def expand(self, value):
        if "{firmware}" not in value:
            return value
        path = Path(os.path.normpath(value.replace("{firmware}", str(self.firmware_root))))
        self.firmware_paths.append(path)
        return str(path)


class Coord(ctypes.Structure):
    _fields_ = [("x", wintypes.SHORT), ("y", wintypes.SHORT)]


class SmallRect(ctypes.Structure):
    _fields_ = [("left", wintypes.SHORT), ("top", wintypes.SHORT),
        ("right", wintypes.SHORT), ("bottom", wintypes.SHORT)]


class ConsoleScreenBufferInfo(ctypes.Structure):
    _fields_ = [("size", Coord), ("cursor", Coord), ("attributes", wintypes.WORD),
        ("window", SmallRect), ("maximum", Coord)]


_console_lock = threading.Lock()


def red_error(text):
    with _console_lock:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetConsoleScreenBufferInfo.argtypes = [wintypes.HANDLE,
            ctypes.POINTER(ConsoleScreenBufferInfo)]
        kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL
        kernel32.SetConsoleTextAttribute.argtypes = [wintypes.HANDLE, wintypes.WORD]
        kernel32.SetConsoleTextAttribute.restype = wintypes.BOOL
        handle = kernel32.GetStdHandle(-12)
        info = ConsoleScreenBufferInfo()
        colored = bool(handle and handle != ctypes.c_void_p(-1).value and
            kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)))
        if colored:
            kernel32.SetConsoleTextAttribute(handle, (info.attributes & 0xFFF0) | 0x000C)
        try:
            print(text, file=sys.stderr, flush=True)
        finally:
            if colored:
                kernel32.SetConsoleTextAttribute(handle, info.attributes)


def error_record_text(record):
    if not isinstance(record, dict):
        return None
    short = record.get("shortError")
    message = record.get("messageBuffer")
    if short and message:
        code = record.get("internalErrorCode")
        internal = f"0x{code & 0xffffffff:08X}" if isinstance(code, int) else str(code or "")
        title = record.get("titleId") or "unknown title"
        return f"PS5 guest error {short} ({internal}, {title}): {message}"

    event_id = record.get("eventId")
    event = record.get("eventStr")
    if isinstance(event, str):
        try:
            event = json.loads(event)
        except json.JSONDecodeError:
            event = {}
    if not isinstance(event, dict):
        return None
    if event_id == "ErrorDialog":
        code = event.get("shortErrorCode") or "unknown code"
        internal = event.get("vshErrorHexCode") or "unknown internal code"
        title = event.get("titleId") or "unknown title"
        message = event.get("description") or "error dialog"
        return f"PS5 guest error dialog {code} ({internal}, {title}): {message}"
    if event_id == "ApplicationError":
        severity = str(event.get("severity", "")).lower()
        if severity not in {"major", "critical", "fatal"}:
            return None
        code = event.get("vshErrorHexCode") or "unknown code"
        title = event.get("appTitleId") or "unknown title"
        kind = event.get("errorType") or f"{severity} application error"
        message = str(event.get("errorMessage") or "").strip()
        return f"PS5 guest {kind} ({code}, {title}): {message}".rstrip()
    return None


class ErrorReporter:
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.object_versions = {}
        self.log_offsets = {}
        self.log_partial = {}
        self.fatal_blocks = {}
        self.reported = set()
        self.error_log = run_dir / "error_report.log"
        self.expected_shutdown = threading.Event()
        self.poll_lock = threading.RLock()

    def begin_expected_shutdown(self):
        with self.poll_lock:
            if self.expected_shutdown.is_set():
                return
            self.poll(final=True)
            self.expected_shutdown.set()

    def report(self, text, key=None):
        text = text.strip()
        key = text if key is None else key
        if text and key not in self.reported:
            self.reported.add(key)
            try:
                with self.error_log.open("a", encoding="utf-8") as output:
                    output.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {text}\n")
            except OSError:
                pass
            red_error(text)

    @staticmethod
    def failure_key(line):
        fields = {}
        for token in line.split():
            if "=" in token:
                name, value = token.split("=", 1)
                fields[name] = value
        if "GUEST_EXEC_FATAL_SIGNAL" in line:
            return ("guest_fatal", fields.get("guest_rva"), fields.get("signal"),
                    fields.get("source"))
        if "outcome=crashed" in line:
            return ("crashed", fields.get("path"), fields.get("status"), fields.get("reason"))
        if "HOST_EXIT path=" in line:
            return ("host_exit", fields.get("path"), fields.get("status"))
        return line

    @staticmethod
    def fatal_source_line(line):
        before, separator, number = line.rpartition(":")
        return bool(separator and number.isdigit() and " in " in before)

    def poll_objects(self):
        objects = self.run_dir / "upper/_system_data/objects"
        if not objects.is_dir():
            return
        for path in objects.iterdir():
            try:
                stat = path.stat()
            except OSError:
                continue
            version = (stat.st_size, stat.st_mtime_ns)
            if not path.is_file() or stat.st_size == 0 or stat.st_size > ERROR_OBJECT_LIMIT or \
                    self.object_versions.get(path) == version:
                continue
            self.object_versions[path] = version
            try:
                text = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeError):
                continue
            decoder = json.JSONDecoder()
            offset = 0
            while offset < len(text):
                while offset < len(text) and text[offset].isspace():
                    offset += 1
                if offset >= len(text):
                    break
                try:
                    record, offset = decoder.raw_decode(text, offset)
                except json.JSONDecodeError:
                    break
                message = error_record_text(record)
                if message:
                    self.report(message)

    def poll_exit_notes(self):
        for path in self.run_dir.glob("fault_provenance.exitnote.*.txt"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if text and not (self.expected_shutdown.is_set() and "HOST_EXIT path=" in text):
                self.report(f"Kyty host crash: {text}")

    def report_fatal_block(self, block):
        if self.expected_shutdown.is_set() and any("ErrorSurfaceLostKHR" in line for line in block):
            return
        for line in block:
            self.report(f"Kyty fatal report: {line}")

    def poll_log(self, path, final=False):
        try:
            size = path.stat().st_size
        except OSError:
            return
        offset = self.log_offsets.get(path, 0)
        if size < offset:
            offset = 0
            self.log_partial[path] = ""
        if size == offset and not final:
            return
        data = b""
        if size != offset:
            try:
                with path.open("rb") as source:
                    source.seek(offset)
                    data = source.read()
                    self.log_offsets[path] = source.tell()
            except OSError:
                return
        text = self.log_partial.get(path, "") + data.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        self.log_partial[path] = ""
        if not final and lines and not lines[-1].endswith(("\n", "\r")):
            self.log_partial[path] = lines.pop()
        block = self.fatal_blocks.pop(path, [])
        for raw in lines:
            line = raw.strip()
            if line in {"--- Fatal Error ---", "--- Error ---"}:
                if block:
                    self.report_fatal_block(block)
                block = [line]
                continue
            if block and line:
                block.append(line)
                if self.fatal_source_line(line) or len(block) >= 3:
                    self.report_fatal_block(block)
                    block = []
                continue
            if "GUEST_EXEC_FATAL_SIGNAL" in line or "outcome=crashed" in line or \
                    "HOST_EXIT path=" in line:
                if self.expected_shutdown.is_set() and "HOST_EXIT path=" in line:
                    continue
                self.report(f"Kyty failure: {line}", self.failure_key(line))
        if final and block:
            self.report_fatal_block(block)
            block = []
        if block:
            self.fatal_blocks[path] = block

    def poll(self, final=False):
        with self.poll_lock:
            self.poll_objects()
            self.poll_exit_notes()
            for path in self.run_dir.glob("kyty.log*"):
                if path.is_file():
                    self.poll_log(path, final)
            host_console = self.run_dir / "host_console.log"
            if host_console.is_file():
                self.poll_log(host_console, final)


def exit_error_text(code):
    value = code & 0xffffffff
    descriptions = {
        0xC0000005: "access violation",
        0xC000001D: "illegal instruction",
        0xC0000374: "heap corruption",
        0xC0000409: "stack buffer overrun or fail-fast",
    }
    description = descriptions.get(value)
    suffix = f" ({description})" if description else ""
    return f"Kyty host terminated with exit code 0x{value:08X}{suffix}."


class StartupInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class ProcessInformation(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class JobBasic(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64), ("flags", wintypes.DWORD),
        ("min_working_set", ctypes.c_size_t), ("max_working_set", ctypes.c_size_t),
        ("active_limit", wintypes.DWORD), ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
        ("scheduling", wintypes.DWORD)]


class JobLimits(ctypes.Structure):
    _fields_ = [("basic", JobBasic), ("io", ctypes.c_uint64 * 6), ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


class ProcessEntry32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]


WindowProcedure = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                                    wintypes.WPARAM, wintypes.LPARAM)


if not hasattr(wintypes, "HCURSOR"):
    wintypes.HCURSOR = wintypes.HICON  # absent from ctypes.wintypes on this Python; winuser.h aliases it to HICON


class WindowClass(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("window_procedure", WindowProcedure),
        ("class_extra", ctypes.c_int), ("window_extra", ctypes.c_int),
        ("instance", wintypes.HINSTANCE), ("icon", wintypes.HICON),
        ("cursor", wintypes.HCURSOR), ("background", wintypes.HBRUSH),
        ("menu_name", wintypes.LPCWSTR), ("class_name", wintypes.LPCWSTR)]


class DisplayBroker:
    FOCUS_VISIBLE_CHILD_MESSAGE = 0x804B

    def __init__(self, on_close=None):
        self.hwnd = 0
        self.closed = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.thread = None
        self.window_procedure = None
        self.resize_procedure = None
        self.on_close = on_close
        self.last_focus_result = None

    def start(self):
        self.thread = threading.Thread(target=self.run, name="KytyDisplayBroker", daemon=True)
        self.thread.start()
        if not self.ready.wait(10):
            raise RuntimeError("host display window creation timed out")
        if self.error is not None:
            raise self.error
        if not self.hwnd:
            raise RuntimeError("host display window was not created")

    def close(self):
        if self.hwnd:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                            wintypes.LPARAM]
            user32.PostMessageW(self.hwnd, 0x0010, 0, 0)
        if self.thread is not None:
            self.thread.join(5)

    def run(self):
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        user32.DefWindowProcW.restype = ctypes.c_ssize_t
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                          wintypes.LPARAM]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND,
            wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p]
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.EnumChildWindows.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.LPARAM]
        user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetWindow.restype = wintypes.HWND
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND,
                                                     ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
        user32.AttachThreadInput.restype = wintypes.BOOL
        user32.SetFocus.argtypes = [wintypes.HWND]
        user32.SetFocus.restype = wintypes.HWND
        user32.GetFocus.restype = wintypes.HWND
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                        wintypes.LPARAM]
        user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, wintypes.UINT]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT,
                                       wintypes.UINT]
        user32.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
        user32.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        instance = kernel32.GetModuleHandleW(None)
        class_name = f"KytyBootDisplay.{os.getpid()}.{secrets.token_hex(4)}"

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        def resize_child(window, packed_size):
            width = packed_size & 0xffff
            height = (packed_size >> 16) & 0xffff
            user32.SetWindowPos(window, 0, 0, 0, width, height, 0x0014)
            return True

        def visible_child(window):
            child = user32.GetWindow(window, 5)
            while child:
                if user32.IsWindowVisible(child):
                    return child
                child = user32.GetWindow(child, 2)
            return 0

        def focus_visible_child(window):
            if user32.GetForegroundWindow() != window:
                return
            child = visible_child(window)
            if not child:
                return
            broker_thread = kernel32.GetCurrentThreadId()
            child_thread = user32.GetWindowThreadProcessId(child, None)
            if not child_thread:
                return
            attached = child_thread == broker_thread or bool(
                user32.AttachThreadInput(broker_thread, child_thread, True))
            focused = False
            if attached:
                try:
                    user32.SetFocus(child)
                    focused = user32.GetFocus() == child
                finally:
                    if child_thread != broker_thread:
                        user32.AttachThreadInput(broker_thread, child_thread, False)
            result = (int(child), int(child_thread), attached, focused)
            if result != self.last_focus_result:
                print(f"NON_AUTHENTIC_INPUT_BRIDGE HOST_DISPLAY_FOCUS child=0x{int(child):x} "
                      f"child_thread={int(child_thread)} attached={int(attached)} "
                      f"focused={int(focused)}", flush=True)
                self.last_focus_result = result

        @WindowProcedure
        def window_procedure(window, message, wparam, lparam):
            if message == 0x0005:
                user32.EnumChildWindows(window, self.resize_procedure, lparam)
                return 0
            if message == 0x0007:
                focus_visible_child(window)
                return 0
            if message == self.FOCUS_VISIBLE_CHILD_MESSAGE:
                focus_visible_child(window)
                return 0
            if message in {0x0100, 0x0101, 0x0102, 0x0104, 0x0105, 0x0106}:
                child = visible_child(window)
                if child:
                    user32.PostMessageW(child, message, wparam, lparam)
                    return 0
            if message == 0x0010:
                if self.on_close is not None:
                    self.on_close()
                self.closed.set()
                user32.DestroyWindow(window)
                return 0
            if message == 0x0002:
                self.closed.set()
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(window, message, wparam, lparam)

        self.resize_procedure = resize_child
        self.window_procedure = window_procedure
        window_class = WindowClass()
        window_class.style = 0x0003
        window_class.window_procedure = self.window_procedure
        window_class.instance = instance
        window_class.cursor = user32.LoadCursorW(None, ctypes.c_void_p(32512))
        window_class.background = gdi32.GetStockObject(4)
        window_class.class_name = class_name
        try:
            atom = user32.RegisterClassW(ctypes.byref(window_class))
            if not atom:
                raise OSError(ctypes.get_last_error(), "RegisterClassW")
            rect = wintypes.RECT(0, 0, 1280, 720)
            style = 0x00CF0000 | 0x02000000
            if not user32.AdjustWindowRectEx(ctypes.byref(rect), style, False, 0):
                raise OSError(ctypes.get_last_error(), "AdjustWindowRectEx")
            width = rect.right - rect.left
            height = rect.bottom - rect.top
            x = max(0, (user32.GetSystemMetrics(0) - width) // 2)
            y = max(0, (user32.GetSystemMetrics(1) - height) // 2)
            self.hwnd = user32.CreateWindowExW(0, class_name, "Kyty PS5", style, x, y, width,
                                                height, None, None, instance, None)
            if not self.hwnd:
                raise OSError(ctypes.get_last_error(), "CreateWindowExW")
            user32.ShowWindow(self.hwnd, 5)
            user32.UpdateWindow(self.hwnd)
            self.ready.set()
            message = wintypes.MSG()
            while True:
                result = user32.GetMessageW(ctypes.byref(message), None, 0, 0)
                if result == 0:
                    break
                if result == -1:
                    raise OSError(ctypes.get_last_error(), "GetMessageW")
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
        except BaseException as error:
            self.error = error
            self.closed.set()
            self.ready.set()
        finally:
            if self.hwnd and user32.IsWindow(self.hwnd):
                user32.DestroyWindow(self.hwnd)
            self.hwnd = 0
            user32.UnregisterClassW(class_name, instance)


class WindowTelemetry:
    HEARTBEAT_SECONDS = 5.0

    def __init__(self, path, broker_window):
        self.path = Path(path)
        self.broker_window = broker_window
        self.last_snapshot = None
        self.last_write = 0.0
        self.failed = False

    @staticmethod
    def window_text(user32, window):
        buffer = ctypes.create_unicode_buffer(257)
        user32.GetWindowTextW(window, buffer, len(buffer))
        return buffer.value

    @staticmethod
    def class_name(user32, window):
        buffer = ctypes.create_unicode_buffer(257)
        user32.GetClassNameW(window, buffer, len(buffer))
        return buffer.value

    @staticmethod
    def window_record(user32, window):
        process_id = wintypes.DWORD()
        thread_id = user32.GetWindowThreadProcessId(window, ctypes.byref(process_id))
        return {
            "hwnd": f"0x{int(window):x}",
            "visible": bool(user32.IsWindowVisible(window)),
            "process_id": int(process_id.value),
            "thread_id": int(thread_id),
            "class": WindowTelemetry.class_name(user32, window),
            "title": WindowTelemetry.window_text(user32, window),
        }

    def snapshot(self):
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetWindow.restype = wintypes.HWND
        user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.IsWindow.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        exists = bool(user32.IsWindow(self.broker_window))
        broker = self.window_record(user32, self.broker_window) if exists else {
            "hwnd": f"0x{int(self.broker_window):x}",
            "visible": False,
            "process_id": 0,
            "thread_id": 0,
            "class": "",
            "title": "",
        }
        children = []
        if exists:
            child = user32.GetWindow(self.broker_window, 5)
            while child:
                children.append(self.window_record(user32, child))
                child = user32.GetWindow(child, 2)
        return {
            "broker_exists": exists,
            "broker": broker,
            "total_children": len(children),
            "visible_children": sum(1 for child in children if child["visible"]),
            "children": children,
        }

    def poll(self, reason, force=False):
        now = time.monotonic()
        try:
            snapshot = self.snapshot()
            changed = snapshot != self.last_snapshot
            if not force and not changed and now - self.last_write < self.HEARTBEAT_SECONDS:
                return
            record = {
                "time_unix_ms": time.time_ns() // 1_000_000,
                "reason": reason,
                "changed": changed,
                **snapshot,
            }
            with self.path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
            self.last_snapshot = snapshot
            self.last_write = now
        except Exception as error:
            if not self.failed:
                self.failed = True
                try:
                    with self.path.open("a", encoding="utf-8") as output:
                        output.write(json.dumps({
                            "time_unix_ms": time.time_ns() // 1_000_000,
                            "reason": "telemetry_error",
                            "error": str(error),
                        }, separators=(",", ":")) + "\n")
                except OSError:
                    pass


def emulator_pids():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32)]
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel32.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot")
    found = set()
    try:
        entry = ProcessEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        present = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            if entry.szExeFile.lower() == "kyty_emulator.exe":
                found.add(int(entry.th32ProcessID))
            present = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return found


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def environment(boot, run_dir, scope, build_id, readbacks, show_services, display_window):
    env = dict(boot.environment)
    env["KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE"] = scope
    env["KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE"] = scope
    env["KYTY_PS5_ICCNVS4_OVERLAY"] = str(run_dir / "mini_a53_nvram.kytycow")
    env["KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER"] = str(run_dir / "upper")
    env["KYTY_DIAGNOSTIC_UNHANDLED_HOST_PROVENANCE_PREFIX"] = str(run_dir / "fault_provenance")
    env["KYTY_DIAGNOSTIC_HOST_DISPLAY_WINDOW"] = hex(display_window)
    env["KYTY_PS5_STARTUP_CACHE_DIR"] = str(CACHE)
    env["KYTY_PS5_STARTUP_CACHE_BUILD_ID"] = build_id
    env["KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE"] = str(boot.token_file)
    env["KYTY_PS5_ENVELOPE_PROVIDER_PORT"] = boot.config.get("provider", "port").strip()
    env["KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS"] = boot.config.get("provider", "timeout_ms").strip()
    if readbacks:
        env["KYTY_DIAGNOSTIC_PRESENT_READBACK"] = str(run_dir / "present")
        env["KYTY_DIAGNOSTIC_PRESENT_READBACK_INTERVAL_MS"] = "200"
    else:
        env.pop("KYTY_DIAGNOSTIC_PRESENT_READBACK", None)
        env.pop("KYTY_DIAGNOSTIC_PRESENT_READBACK_INTERVAL_MS", None)
    if show_services:
        env["KYTY_SHOW_SERVICE_WINDOWS"] = "1"
    else:
        env.pop("KYTY_SHOW_SERVICE_WINDOWS", None)
    for key in tuple(os.environ):
        if key.upper().startswith("KYTY_"):
            os.environ.pop(key)
    os.environ.update(env)
    return env


def launch(boot, run_dir, log, reporter, display):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernelbase = ctypes.WinDLL("KernelBase", use_last_error=True)
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfo), ctypes.POINTER(ProcessInformation)]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernelbase.VirtualAlloc2.restype = ctypes.c_void_p
    kernelbase.VirtualAlloc2.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
        wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]

    startup = StartupInfo()
    startup.cb = ctypes.sizeof(startup)
    process = ProcessInformation()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW")
    created = False
    assigned = False
    resumed = False
    telemetry = WindowTelemetry(run_dir / "window_telemetry.log", display.hwnd)
    telemetry.poll("before_host_launch", force=True)
    try:
        limits = JobLimits()
        limits.basic.flags = 0x2000
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject")
        command = ctypes.create_unicode_buffer(
            f'"{boot.exe}" --game "{boot.game}" --sysroot "{boot.sysroot}" '
            f'--printf-direction File --printf-output-file "{log}"')
        host_console = run_dir / "host_console.log"
        with open(os.devnull, "rb", buffering=0) as null_input, \
                host_console.open("ab", buffering=0) as console_output:
            input_handle = msvcrt.get_osfhandle(null_input.fileno())
            output_handle = msvcrt.get_osfhandle(console_output.fileno())
            os.set_handle_inheritable(input_handle, True)
            os.set_handle_inheritable(output_handle, True)
            startup.dwFlags |= 0x00000100
            startup.hStdInput = input_handle
            startup.hStdOutput = output_handle
            startup.hStdError = output_handle
            try:
                success = kernel32.CreateProcessW(str(boot.exe), command, None, None, True, 0x08000004,
                                                  None, str(run_dir), ctypes.byref(startup),
                                                  ctypes.byref(process))
            finally:
                os.set_handle_inheritable(input_handle, False)
                os.set_handle_inheritable(output_handle, False)
            if not success:
                raise OSError(ctypes.get_last_error(), "CreateProcessW")
        created = True
        if not kernel32.AssignProcessToJobObject(job, process.hProcess):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject")
        assigned = True
        reserved = kernelbase.VirtualAlloc2(process.hProcess, ctypes.c_void_p(0x400000), 0x110000,
                                            0x2000 | 0x40000, 1, None, 0)
        if reserved != 0x400000:
            raise RuntimeError(f"static exec reservation failed: {reserved}")
        previous = kernel32.ResumeThread(process.hThread)
        if previous != 1:
            raise OSError(ctypes.get_last_error(), f"ResumeThread returned {previous}")
        resumed = True
        print(f"Kyty host process {process.dwProcessId} started.", flush=True)
        print("Close this console or press Ctrl+C to stop the complete boot job.", flush=True)
        while True:
            wait = kernel32.WaitForSingleObject(process.hProcess, 500)
            telemetry.poll("host_running")
            if display.closed.is_set():
                telemetry.poll("display_closed", force=True)
                kernel32.TerminateJobObject(job, 0xC000013A)
                kernel32.WaitForSingleObject(process.hProcess, 5000)
                print("Kyty display window closed; boot job stopped.", flush=True)
                return 130
            reporter.poll()
            if wait == 0:
                break
            if wait != 258:
                raise OSError(ctypes.get_last_error(), f"WaitForSingleObject returned {wait}")
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(process.hProcess, ctypes.byref(exit_code)):
            raise OSError(ctypes.get_last_error(), "GetExitCodeProcess")
        telemetry.poll("host_exited", force=True)
        reporter.poll(final=True)
        return int(exit_code.value)
    except KeyboardInterrupt:
        if assigned:
            kernel32.TerminateJobObject(job, 0xC000013A)
        elif created:
            kernel32.TerminateProcess(process.hProcess, 0xC000013A)
        return 130
    except BaseException:
        if assigned:
            kernel32.TerminateJobObject(job, 1)
        elif created:
            kernel32.TerminateProcess(process.hProcess, 1)
        raise
    finally:
        telemetry.poll("launch_final", force=True)
        reporter.poll(final=True)
        if created:
            kernel32.CloseHandle(process.hThread)
            kernel32.CloseHandle(process.hProcess)
        kernel32.CloseHandle(job)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--show-services", action="store_true")
    parser.add_argument("--readbacks", action="store_true")
    args = parser.parse_args()
    boot = Boot()
    if boot.token_file is None:
        raise RuntimeError(f"[provider] token_file is not set in {CONFIG}")
    readbacks = args.readbacks or boot.config.getboolean("boot", "readbacks")
    show_services = args.show_services or boot.config.getboolean("boot", "show_services")
    required = [boot.exe, boot.exe.parent / "libwinpthread-1.dll", boot.token_file, *boot.firmware_paths]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("missing Kyty boot input: " + ", ".join(missing))
    if boot.psnow.stat().st_size != 200 or sha256(boot.psnow) != PSNOW_OBSERVATION_SHA256:
        raise RuntimeError("PsNow authorization observation identity mismatch")
    active = emulator_pids()
    if active:
        raise RuntimeError("Kyty is already running: " + ", ".join(str(pid) for pid in sorted(active)))
    stamp = time.strftime("%Y%m%d_%H%M%S") + "_" + secrets.token_hex(2)
    scope = "boot_" + secrets.token_hex(6)
    run_dir = boot.runs / stamp
    run_dir.mkdir(parents=True)
    log = run_dir / "kyty.log"
    binary_sha256 = sha256(boot.exe)
    reporter = ErrorReporter(run_dir)
    display = DisplayBroker(reporter.begin_expected_shutdown)
    display.start()
    try:
        env = environment(boot, run_dir, scope, binary_sha256, readbacks, show_services, display.hwnd)
        manifest = {
            "created_host_unix": int(time.time()),
            "binary": str(boot.exe),
            "binary_sha256": binary_sha256,
            "firmware": str(boot.game),
            "firmware_root": str(boot.firmware_root),
            "boot_profile_sha256": sha256(PROFILE),
            "scope": scope,
            "log": str(log),
            "host_console_log": str(run_dir / "host_console.log"),
            "error_report_log": str(run_dir / "error_report.log"),
            "window_telemetry_log": str(run_dir / "window_telemetry.log"),
            "window_telemetry_enabled": True,
            "single_visible_window": not show_services,
            "persistent_host_display": True,
            "present_readbacks": readbacks,
            "diagnostic_ipmi_capability62_standin": env.get("KYTY_DIAGNOSTIC_IPMI_CAPABILITY62_STANDIN"),
            "diagnostic_authinfo_compositor_client": env.get("KYTY_DIAGNOSTIC_AUTHINFO_COMPOSITOR_CLIENT"),
            "diagnostic_vdeccore": env.get("KYTY_DIAGNOSTIC_VDECCORE") == "1",
            "diagnostic_host_input_hid_pad": env.get("KYTY_DIAGNOSTIC_HOST_INPUT_HID_PAD") == "1",
            "diagnostic_mbus_uninitialized_guard": env.get("KYTY_DIAGNOSTIC_MBUS_UNINITIALIZED_GUARD") == "1",
            "diagnostic_puputil_ipmi_admission": env.get("KYTY_DIAGNOSTIC_PUPUTIL_IPMI_ADMISSION") == "1",
            "diagnostic_video_arbitration_coordination_wait":
                env.get("KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT") == "1",
            "psnow_authorization_observation": str(boot.psnow),
            "psnow_authorization_observation_sha256": PSNOW_OBSERVATION_SHA256,
            "immutable_metadata_cache": str(CACHE),
            "envelope_provider_timeout_ms": int(env["KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS"]),
        }
        (run_dir / "boot.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Boot directory: {run_dir}")
        print(f"Binary SHA-256: {manifest['binary_sha256']}")
        print("Mode: diagnostic coordinated PS5 boot; this is not a fully authentic firmware claim.")
        code = launch(boot, run_dir, log, reporter, display)
    finally:
        display.close()
    print(f"Kyty host exit code: 0x{code:08x}")
    if code not in {0, 130}:
        red_error(exit_error_text(code))
    return code if 0 <= code <= 255 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        red_error(f"Kyty boot failed: {error}")
        raise SystemExit(1)
