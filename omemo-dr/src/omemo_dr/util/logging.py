from typing import Any

import logging
from collections.abc import MutableMapping


class SessionContextAdapter(logging.LoggerAdapter):  # pyright: ignore
    def process(
        self, msg: str, kwargs: MutableMapping[str, Any]
    ) -> tuple[str, MutableMapping[str, Any]]:
        assert self.extra is not None
        if self.extra["context"] is None:
            return msg, kwargs
        return f'({self.extra["context"]}) {msg}', kwargs
