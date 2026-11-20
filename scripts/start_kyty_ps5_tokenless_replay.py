import argparse
import configparser
import importlib.util
import os
import secrets
import sys
import threading
from pathlib import Path

import replay_provider_proxy as proxy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--runtime-store-root", type=Path)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--launcher-source", type=Path)
    parser.add_argument("--diagnostic-virtual-usb-pad", action="store_true")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    args, boot_args = parser.parse_known_args()
    if not 0 <= args.proxy_port <= 65535 or args.timeout <= 0 or args.max_bytes <= 0:
        parser.error("invalid replay limits")
    project = args.project.resolve(strict=True)
    profile = args.profile.resolve(strict=True)
    emulator = args.emulator.resolve(strict=True)
    launcher = (args.launcher_source or project / "scripts" / "start_kyty_ps5.py").resolve(strict=True)
    normal_config = configparser.ConfigParser()
    if not normal_config.read(project / "kyty.ini", encoding="utf-8"):
        raise RuntimeError("project configuration unavailable")
    if args.proxy_port != 0 and args.proxy_port == normal_config.getint("provider", "port"):
        raise RuntimeError("replay port must differ from live provider port")
    source_store = proxy.Store(args.store.resolve(strict=True))
    verified = source_store.verify()
    if verified["conflicts"]:
        raise RuntimeError("replay store contains conflicting answers")
    runtime_root = (args.runtime_store_root or project / "evidence" / "runs").resolve()
    runtime_root.mkdir(parents=True, exist_ok=True)
    runtime_path = runtime_root / ("replay_store_" + secrets.token_hex(8))
    runtime_path.mkdir(parents=True, exist_ok=False)
    proxy.private_directory(runtime_path)
    store = proxy.Store(source_store.path, events_path=runtime_path / "events.jsonl")
    print("Replay events:", store.events_path, flush=True)
    token = secrets.token_bytes(32)
    spec = importlib.util.spec_from_file_location("kyty_tokenless_replay_launcher", launcher)
    if spec is None or spec.loader is None:
        raise RuntimeError("launcher unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = project
    module.CONFIG = project / "kyty.ini"
    module.CACHE = project / "runtime" / "cache" / "immutable_metadata"
    module.PROFILE = profile
    original_boot = module.Boot
    proxy_port = args.proxy_port

    class ReplayBoot(original_boot):
        def __init__(self):
            super().__init__()
            self.exe = emulator
            self.token_file = None
            self.config.set("provider", "token_file", "")
            self.config.set("provider", "offline_replay", "yes")
            self.config.set("provider", "port", str(proxy_port))
            self.environment["KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX"] = token.hex()
            if args.diagnostic_virtual_usb_pad:
                self.environment["KYTY_DIAGNOSTIC_VIRTUAL_USB_PAD"] = "1"

    module.Boot = ReplayBoot
    os.environ["PATH"] = str(emulator.parent) + os.pathsep + os.environ.get("PATH", "")
    sys.argv = [str(launcher), *boot_args]
    with proxy.Server(("127.0.0.1", args.proxy_port), proxy.Handler) as server:
        proxy_port = server.server_address[1]
        server.mode = "replay"
        server.store = store
        server.token = token
        server.upstream_port = None
        server.timeout = args.timeout
        server.max_bytes = args.max_bytes
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2})
        thread.start()
        try:
            print("Mode: tokenless exact-cache replay; verified records:", verified["records"], flush=True)
            return module.main()
        finally:
            server.shutdown()
            thread.join()
            os.environ.pop("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX", None)


if __name__ == "__main__":
    sys.exit(main())
