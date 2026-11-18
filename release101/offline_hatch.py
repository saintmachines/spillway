"""Invoke the existing cached build backend with network operations denied."""
import runpy
import sys


def deny(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "socket.gethostbyname",
                 "socket.sendto", "socket.sendmsg", "os.system"}:
        raise RuntimeError("Offline packaging blocks " + event)


sys.addaudithook(deny)
sys.argv[0] = "hatchling"
runpy.run_module("hatchling", run_name="__main__")
