"""Connector interfaces shared by native collectors and CSPM adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from denali.domain import ConnectorCapabilities, InventoryBatch


@dataclass(frozen=True, slots=True)
class ConnectorContext:
    tenant_id: str
    connection_id: str
    scope: Mapping[str, str]


class Connector(Protocol):
    connector_id: str
    capabilities: ConnectorCapabilities

    def collect_inventory(self, context: ConnectorContext) -> InventoryBatch:
        """Collect one explicit scope, including its coverage declaration."""

