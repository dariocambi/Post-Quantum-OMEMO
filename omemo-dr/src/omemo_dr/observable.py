from __future__ import annotations

from typing import Any

import logging
from collections import defaultdict
from collections.abc import Callable


class Observable:
    def __init__(self) -> None:
        self._log = logging.getLogger(__name__)
        self._callbacks: defaultdict[str, list[Callable[..., Any]]] = defaultdict(list)

    def register_signal(self, signal_name: str, func: Callable[..., Any]) -> None:
        self._callbacks[signal_name].append(func)

    def _unregister_signals(self) -> None:
        self._callbacks = defaultdict(list)

    def _notify(self, signal_name: str, *args: Any, **kwargs: dict[str, Any]) -> None:
        self._log.info("Signal: %s", signal_name)
        callbacks = self._callbacks.get(signal_name, [])
        for func in callbacks:
            func(self, signal_name, *args, **kwargs)
