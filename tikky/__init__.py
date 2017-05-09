from .client import TikkyClient, TikkyError


version_info = (0, 0, 1)
__version__ = '.'.join(map(str, version_info))

__all__ = [
    'TikkyClient',
    'TikkyError',
]
