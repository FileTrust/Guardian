"""Finish the current protocol iteration before an intentional service stop."""
import signal
import os
import threading

STOP = threading.Event()


def install():
    STOP.clear()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    expected = os.environ.get("FILETRUST_GUARDIAN_SUPERVISOR_PID", "")
    if expected.isdigit():
        def watch_parent():
            while not STOP.wait(0.5):
                if os.getppid() != int(expected):
                    STOP.set()
                    return
        threading.Thread(target=watch_parent, daemon=True, name="supervisor-liveness").start()


def waiting(seconds):
    return STOP.wait(seconds)
