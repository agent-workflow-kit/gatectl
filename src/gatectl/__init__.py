"""gatectl: policy decisions (allow / deny / escalate) with first-class shadow mode."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("gatectl")
except PackageNotFoundError:  # run from a source tree that was never installed
    __version__ = "0.0.0+unknown"
