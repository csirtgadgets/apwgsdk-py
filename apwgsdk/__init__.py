from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
VERSION = __version__

from .client import *