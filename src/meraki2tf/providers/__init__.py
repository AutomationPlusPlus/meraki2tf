"""Configuration providers: live cloud API and offline JSON dump.

Both implement the same :class:`~meraki2tf.providers.base.ConfigurationProvider`
protocol so the translation pipeline is agnostic to where the network
graph came from — structural parity between modes is guaranteed by the
interface, not by convention.
"""

from meraki2tf.providers.base import ConfigurationProvider, OperationNotInSnapshotError
from meraki2tf.providers.dump import DumpProvider
from meraki2tf.providers.live import LiveProvider

__all__ = [
    "ConfigurationProvider",
    "DumpProvider",
    "LiveProvider",
    "OperationNotInSnapshotError",
]
