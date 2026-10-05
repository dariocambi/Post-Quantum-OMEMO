from __future__ import annotations

from typing import cast
from typing import Optional

import google.protobuf.message

from . import storage_pb2
from .sessionstate import SessionState
from .sessionstate import SessionStructureProto

ARCHIVED_STATES_MAX_LENGTH = 40


class SessionRecord:
    def __init__(
        self,
        session_state: Optional[SessionState] = None,
        serialized: Optional[bytes] = None,
    ) -> None:
        self._previous_states: list[SessionState] = []
        if session_state:
            self._session_state = session_state
            self._fresh = False

        elif serialized:
            record = cast(
                RecordStructureProto, storage_pb2.RecordStructure()  # pyright: ignore
            )
            record.ParseFromString(serialized)
            self._session_state = SessionState(record.currentSession)
            self._fresh = False
            for previous_structure in record.previousSessions:
                self._previous_states.append(SessionState(previous_structure))

        else:
            self._fresh = True
            self._session_state = SessionState()

    def has_session_state(self, version: int, alice_base_key: bytes) -> bool:
        if (
            self._session_state.get_session_version() == version
            and alice_base_key == self._session_state.get_alice_base_key()
        ):
            return True

        for state in self._previous_states:
            if (
                state.get_session_version() == version
                and alice_base_key == state.get_alice_base_key()
            ):
                return True

        return False

    def get_session_state(self) -> SessionState:
        return self._session_state

    def get_previous_session_states(self) -> list[SessionState]:
        return self._previous_states

    def is_fresh(self) -> bool:
        return self._fresh

    def archive_current_state(self) -> None:
        self.promote_state(SessionState())

    def promote_state(self, promoted_state: SessionState) -> None:
        self._previous_states.insert(0, self._session_state)
        self._session_state = promoted_state
        if len(self._previous_states) > ARCHIVED_STATES_MAX_LENGTH:
            self._previous_states.pop()

    def set_state(self, session_state: SessionState) -> None:
        self._session_state = session_state

    def serialize(self) -> bytes:
        previous_structures = [
            previous_state.get_structure() for previous_state in self._previous_states
        ]
        record = cast(
            RecordStructureProto, storage_pb2.RecordStructure()  # pyright: ignore
        )
        record.currentSession.MergeFrom(self._session_state.get_structure())
        record.previousSessions.extend(previous_structures)

        return record.SerializeToString()


class RecordStructureProto(google.protobuf.message.Message):
    currentSession: SessionStructureProto
    previousSessions: list[SessionStructureProto]
