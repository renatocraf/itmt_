"""Data classes for Threat Model representation (Microsoft .tm7 format)."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class PropertyTM7:
    """Property of a diagram element (e.g. name, value, list options)."""
    display_name: str
    name: Optional[str]
    value: Optional[str]
    selected_index: Optional[int] = None
    values: List[str] = field(default_factory=list)


@dataclass
class ElementTM7:
    """Generic diagram element (Process, External Interactor, Data Store, etc.)."""
    guid: str
    type_id: str
    generic_type_id: str
    name: str
    properties: List[PropertyTM7] = field(default_factory=list)
    # Position (left, top, width, height)
    left: Optional[float] = None
    top: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None


@dataclass
class DataFlowTM7:
    """Data flow between two diagram elements."""
    guid: str
    name: str
    source_guid: str
    target_guid: str
    properties: List[PropertyTM7] = field(default_factory=list)
    crossed_boundaries: List[str] = field(default_factory=list)  # GUIDs of crossed trust boundaries


@dataclass
class TrustBoundaryTM7:
    """Trust boundary (rectangular region) in a diagram."""
    guid: str
    name: str
    left: float
    top: float
    width: float
    height: float


@dataclass
class ThreatTM7:
    """Identified threat from the threat model (category, description, flow/element refs)."""
    threat_id: str
    type_id: str
    title: str
    category: str
    description: str
    priority: str
    state: str
    source_guid: str
    target_guid: str
    flow_guid: Optional[str] = None


@dataclass
class DiagramTM7:
    """Complete diagram: elements, data flows, and trust boundaries."""
    guid: str
    name: str
    elements: List[ElementTM7] = field(default_factory=list)
    dataflows: List[DataFlowTM7] = field(default_factory=list)
    trust_boundaries: List[TrustBoundaryTM7] = field(default_factory=list)


@dataclass
class ThreatModelTM7:
    """Full threat model: version, diagrams, threats, and meta information."""
    version: str
    diagrams: List[DiagramTM7] = field(default_factory=list)
    threats: List[ThreatTM7] = field(default_factory=list)
    meta_info: Dict[str, str] = field(default_factory=dict)

