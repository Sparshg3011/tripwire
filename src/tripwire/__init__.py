from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tripwire-agent")
except PackageNotFoundError:  # a source tree on sys.path that was never installed
    __version__ = "unknown"
