"""Mock FaceHello auth service for the test VM only (no camera, no models).

Speaks the same message-mode named-pipe protocol as face_hello/service.py for the commands the
Credential Provider uses (ping, auth_start, auth_poll) and always reports success for the account
name in C:\\Users\\Public\\mock-user.txt. The provider checks that the pipe server is LocalSystem,
so this must run as SYSTEM (the test script starts it from a SYSTEM scheduled task).
"""
import json
import time

import win32file
import win32pipe

PIPE_NAME = r"\\.\pipe\FaceHello"
BUF = 65536
USER_FILE = r"C:\Users\Public\mock-user.txt"
LOG_FILE = r"C:\Users\Public\mock-service.log"


def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(time.strftime("%H:%M:%S ") + msg + "\n")
    except OSError:
        pass


def user():
    try:
        with open(USER_FILE, encoding="utf-8") as f:
            return f.read().strip() or "tester"
    except OSError:
        return "tester"


def handle(req):
    cmd = req.get("cmd")
    if cmd == "ping":
        return {"ok": True, "ready": True, "users": [user()], "version": "mock", "protocol": 1}
    if cmd == "auth_start":
        return {"ok": True, "done": False}
    if cmd == "auth_poll":
        return {"ok": True, "done": True, "instruction": "mock", "success": True,
                "user": user(), "similarity": 0.99}
    return {"ok": False, "reason": "unknown cmd"}


def serve_one():
    pipe = win32pipe.CreateNamedPipe(
        PIPE_NAME, win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
        1, BUF, BUF, 0, None)
    try:
        win32pipe.ConnectNamedPipe(pipe, None)
        try:
            req = json.loads(win32file.ReadFile(pipe, BUF)[1].decode("utf-8"))
            resp = handle(req)
            log(f"{req.get('cmd')} -> {resp.get('user', '')} ok={resp.get('ok')}")
        except Exception as exc:  # noqa: BLE001
            resp = {"ok": False, "reason": str(exc)}
        try:
            win32file.WriteFile(pipe, json.dumps(resp).encode("utf-8"))
            win32file.FlushFileBuffers(pipe)
        except Exception:  # noqa: BLE001
            pass
        win32pipe.DisconnectNamedPipe(pipe)
    finally:
        win32file.CloseHandle(pipe)


if __name__ == "__main__":
    log("mock service start")
    while True:
        try:
            serve_one()
        except Exception as exc:  # noqa: BLE001
            log(f"serve error: {exc}")
            time.sleep(1)
