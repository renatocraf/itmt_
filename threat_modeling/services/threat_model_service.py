"""Threat Model Service - Business logic for threat model parsing and validation."""
import tempfile
import os
from typing import Dict, Optional

from ..models.parser import TM7Parser, dataflows_to_json, threat_model_to_json, generate_tmt_dataframe
from ..models.threat_model import ThreatModelTM7, DiagramTM7


class ThreatModelService:
    """Service for parsing .tm7 files, building diagram/threat JSON, and validating threat models."""

    @staticmethod
    def parse_tm7_file(xml_content: str) -> ThreatModelTM7:
        """
        Parse a .tm7 file content.
        
        Args:
            xml_content: XML content as string
            
        Returns:
            ThreatModelTM7 object
        """
        parser = TM7Parser(xml_content)
        return parser.parse()
    
    @staticmethod
    def process_uploaded_file(uploaded_file) -> ThreatModelTM7:
        """
        Process an uploaded .tm7 file (file-like with .getvalue() or .read()).

        Args:
            uploaded_file: File-like object (e.g. Flask FileStorage) with .getvalue()
                returning bytes, or compatible interface.

        Returns:
            Parsed ThreatModelTM7 instance.

        Raises:
            ValueError: If no file, empty content, or decode error.
            Exception: If XML parsing fails.
        """
        if uploaded_file is None:
            raise ValueError("No file uploaded")
        
        try:
            xml_content = uploaded_file.getvalue().decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError(f"Failed to decode file content: {str(e)}")
        
        if not xml_content or len(xml_content.strip()) == 0:
            raise ValueError("File is empty")
        
        return ThreatModelService.parse_tm7_file(xml_content)
    
    @staticmethod
    def get_diagram_json(threat_model: ThreatModelTM7, diagram_index: int = 0) -> Dict:
        """
        Convert a diagram to JSON format.
        
        Args:
            threat_model: ThreatModelTM7 object
            diagram_index: Index of the diagram to convert
            
        Returns:
            Dictionary with dataflow information
        """
        if diagram_index >= len(threat_model.diagrams):
            raise ValueError(f"Diagram index {diagram_index} out of range")
        
        selected_diagram = threat_model.diagrams[diagram_index]
        return dataflows_to_json(selected_diagram, create_file=False)
    
    @staticmethod
    def get_threat_data_json(threat_model: ThreatModelTM7) -> str:
        """
        Convert threat model threats to JSON string.
        
        Args:
            threat_model: ThreatModelTM7 object
            
        Returns:
            JSON string with threat data
        """
        return threat_model_to_json(threat_model)
    
    @staticmethod
    def get_diagram_threats(threat_model: ThreatModelTM7, diagram_index: int) -> list:
        """
        Get threats associated with a specific diagram.
        
        Args:
            threat_model: ThreatModelTM7 object
            diagram_index: Index of the diagram
            
        Returns:
            List of ThreatTM7 objects associated with the diagram
        """
        if diagram_index >= len(threat_model.diagrams):
            raise ValueError(f"Diagram index {diagram_index} out of range")
        
        selected_diagram = threat_model.diagrams[diagram_index]
        
        # Get all GUIDs from the diagram (elements and dataflows)
        element_guids = {elem.guid for elem in selected_diagram.elements}
        flow_guids = {flow.guid for flow in selected_diagram.dataflows}
        
        # Filter threats that are associated with this diagram
        # A threat is associated if its source_guid, target_guid, or flow_guid
        # matches an element or flow in the diagram
        diagram_threats = []
        for threat in threat_model.threats:
            if (threat.source_guid in element_guids or 
                threat.target_guid in element_guids or
                (threat.flow_guid and threat.flow_guid in flow_guids)):
                diagram_threats.append(threat)
        
        return diagram_threats
    
    @staticmethod
    def get_diagram_threats_json(threat_model: ThreatModelTM7, diagram_index: int) -> str:
        """
        Get threats for a specific diagram as JSON string.
        
        Args:
            threat_model: ThreatModelTM7 object
            diagram_index: Index of the diagram
            
        Returns:
            JSON string with threat data for the diagram
        """
        diagram_threats = ThreatModelService.get_diagram_threats(threat_model, diagram_index)
        
        # Create a temporary threat model with only the diagram threats
        from ..models.threat_model import ThreatModelTM7
        temp_threat_model = ThreatModelTM7(
            version=threat_model.version,
            diagrams=threat_model.diagrams,
            threats=diagram_threats,
            meta_info=threat_model.meta_info
        )
        
        return threat_model_to_json(temp_threat_model)
    
    @staticmethod
    def generate_threat_dataframe(threat_data: str):
        """
        Generate DataFrame from threat data JSON.
        
        Args:
            threat_data: JSON string with threat data
            
        Returns:
            pandas DataFrame
        """
        return generate_tmt_dataframe(threat_data)
    
    @staticmethod
    def validate_threat_model(threat_model: ThreatModelTM7) -> tuple[bool, Optional[str]]:
        """
        Validate threat model has required data.
        
        Args:
            threat_model: ThreatModelTM7 object
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not threat_model.diagrams:
            return False, "No diagrams found in the threat model"
        
        return True, None

