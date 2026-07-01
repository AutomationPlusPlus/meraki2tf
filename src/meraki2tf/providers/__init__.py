"""Dual-modality ingestion providers: live cloud API and offline JSON dump.

Both implement the :class:`~meraki2tf.providers.base.MerakiDataProvider`
protocol and emit identical :class:`~meraki2tf.models.NetworkGraph`
domain models, so downstream components stay data-source agnostic.
"""

from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.providers.dump import MalformedDumpError, StaticJsonDataProvider
from meraki2tf.providers.live import LiveApiDataProvider, LiveDispatchError

__all__ = [
    "LiveApiDataProvider",
    "LiveDispatchError",
    "MalformedDumpError",
    "MerakiDataProvider",
    "StaticJsonDataProvider",
]
