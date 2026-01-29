import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json
import pandas as pd

# Namespaces utilizados no arquivo .tm7
NAMESPACES = {
    'tm': 'http://schemas.datacontract.org/2004/07/ThreatModeling.Model',
    'abs': 'http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts',
    'kb': 'http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase',
    'i': 'http://www.w3.org/2001/XMLSchema-instance',
    'z': 'http://schemas.microsoft.com/2003/10/Serialization/',
    'a': 'http://schemas.microsoft.com/2003/10/Serialization/Arrays'
}

@dataclass
class PropertyTM7:
    """Representa uma propriedade de um elemento"""
    display_name: str
    name: Optional[str]
    value: Optional[str]
    selected_index: Optional[int] = None
    values: List[str] = field(default_factory=list)

@dataclass
class ElementTM7:
    """Representa um elemento genérico (Process, External Interactor, Data Store, etc.)"""
    guid: str
    type_id: str
    generic_type_id: str
    name: str
    properties: List[PropertyTM7] = field(default_factory=list)
    # Propriedades de posicionamento
    left: Optional[float] = None
    top: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None

@dataclass
class DataFlowTM7:
    """Representa um fluxo de dados entre elementos"""
    guid: str
    name: str
    source_guid: str
    target_guid: str
    properties: List[PropertyTM7] = field(default_factory=list)
    crossed_boundaries: List[str] = field(default_factory=list)  # GUIDs das boundaries cruzadas

@dataclass
class TrustBoundaryTM7:
    """Representa uma fronteira de confiança"""
    guid: str
    name: str
    left: float
    top: float
    width: float
    height: float

@dataclass
class ThreatTM7:
    """Representa uma ameaça identificada"""
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
    """Representa um diagrama completo"""
    guid: str
    name: str
    elements: List[ElementTM7] = field(default_factory=list)
    dataflows: List[DataFlowTM7] = field(default_factory=list)
    trust_boundaries: List[TrustBoundaryTM7] = field(default_factory=list)

@dataclass
class ThreatModelTM7:
    """Representa o modelo de ameaças completo"""
    version: str
    diagrams: List[DiagramTM7] = field(default_factory=list)
    threats: List[ThreatTM7] = field(default_factory=list)
    meta_info: Dict[str, str] = field(default_factory=dict)


class TM7Parser:
    """Parser para arquivos .tm7 do Microsoft Threat Modeling Tool"""
    
    def __init__(self, xml_content: str):
        self.root = ET.fromstring(xml_content)
        
    def parse(self) -> ThreatModelTM7:
        """Parse completo do arquivo .tm7"""
        model = ThreatModelTM7(version=self._get_version())
        
        # Parse diagramas
        model.diagrams = self._parse_diagrams()
        
        # Parse ameaças
        model.threats = self._parse_threats()
        
        # Parse meta informações
        model.meta_info = self._parse_meta_info()
        
        return model
    
    def _get_version(self) -> str:
        """Obtém a versão do threat model"""
        version_elem = self.root.find('.//tm:Version', NAMESPACES)
        return version_elem.text if version_elem is not None else "Unknown"
    
    def _parse_diagrams(self) -> List[DiagramTM7]:
        """Parse todos os diagramas"""
        diagrams = []
        drawing_surfaces = self.root.findall('.//tm:DrawingSurfaceList/tm:DrawingSurfaceModel', NAMESPACES)
        
        for surface in drawing_surfaces:
            diagram = self._parse_diagram(surface)
            diagrams.append(diagram)
        
        return diagrams
    
    def _parse_diagram(self, surface_elem) -> DiagramTM7:
        """Parse um diagrama individual"""
        guid = self._get_text(surface_elem, './/abs:Guid', NAMESPACES)
        name = self._get_property_value(surface_elem, 'Name')
        
        diagram = DiagramTM7(guid=guid, name=name)
        
        # Parse elementos (Process, External Interactor, Data Store)
        borders = surface_elem.find('.//tm:Borders', NAMESPACES)
        if borders is not None:
            for kv_pair in borders.findall('.//a:KeyValueOfguidanyType', NAMESPACES):
                element = self._parse_element(kv_pair)
                if element:
                    if element.generic_type_id == 'GE.TB.B':
                        # É uma Trust Boundary
                        tb = TrustBoundaryTM7(
                            guid=element.guid,
                            name=element.name,
                            left=element.left,
                            top=element.top,
                            width=element.width,
                            height=element.height
                        )
                        diagram.trust_boundaries.append(tb)
                    else:
                        diagram.elements.append(element)
        
        # Parse dataflows
        lines = surface_elem.find('.//tm:Lines', NAMESPACES)
        if lines is not None:
            for kv_pair in lines.findall('.//a:KeyValueOfguidanyType', NAMESPACES):
                dataflow = self._parse_dataflow(kv_pair)
                if dataflow:
                    diagram.dataflows.append(dataflow)
        
        # Detectar quais boundaries cada dataflow cruza
        self._detect_boundary_crossings(diagram)
        
        return diagram
    
    def _parse_element(self, kv_elem) -> Optional[ElementTM7]:
        """Parse um elemento (Process, External Interactor, etc.)"""
        value_elem = kv_elem.find('.//a:Value', NAMESPACES)
        if value_elem is None:
            return None
        
        guid = self._get_text(value_elem, './/abs:Guid', NAMESPACES)
        type_id = self._get_text(value_elem, './/abs:TypeId', NAMESPACES)
        generic_type_id = self._get_text(value_elem, './/abs:GenericTypeId', NAMESPACES)
        name = self._get_property_value(value_elem, 'Name')
        
        # Propriedades de posição
        left = self._get_float(value_elem, './/abs:Left', NAMESPACES)
        top = self._get_float(value_elem, './/abs:Top', NAMESPACES)
        width = self._get_float(value_elem, './/abs:Width', NAMESPACES)
        height = self._get_float(value_elem, './/abs:Height', NAMESPACES)
        
        properties = self._parse_properties(value_elem)
        
        return ElementTM7(
            guid=guid,
            type_id=type_id,
            generic_type_id=generic_type_id,
            name=name,
            properties=properties,
            left=left,
            top=top,
            width=width,
            height=height
        )
    
    def _parse_dataflow(self, kv_elem) -> Optional[DataFlowTM7]:
        """Parse um dataflow"""
        value_elem = kv_elem.find('.//a:Value', NAMESPACES)
        if value_elem is None:
            return None
        
        guid = self._get_text(value_elem, './/abs:Guid', NAMESPACES)
        name = self._get_property_value(value_elem, 'Name')
        source_guid = self._get_text(value_elem, './/abs:SourceGuid', NAMESPACES)
        target_guid = self._get_text(value_elem, './/abs:TargetGuid', NAMESPACES)
        
        properties = self._parse_properties(value_elem)
        
        return DataFlowTM7(
            guid=guid,
            name=name,
            source_guid=source_guid,
            target_guid=target_guid,
            properties=properties
        )
    
    def _parse_properties(self, elem) -> List[PropertyTM7]:
        """Parse propriedades de um elemento"""
        properties = []
        props_elem = elem.find('.//abs:Properties', NAMESPACES)
        
        if props_elem is None:
            return properties
        
        for any_type in props_elem.findall('.//a:anyType', NAMESPACES):
            prop_type = any_type.get('{http://www.w3.org/2001/XMLSchema-instance}type', '')
            
            display_name = self._get_text(any_type, './/kb:DisplayName', NAMESPACES)
            name = self._get_text(any_type, './/kb:Name', NAMESPACES)
            value = self._get_text(any_type, './/kb:Value', NAMESPACES)
            
            # Parse lista de valores para ListDisplayAttribute
            values = []
            selected_index = None
            if 'ListDisplayAttribute' in prop_type:
                value_array = any_type.find('.//kb:Value', NAMESPACES)
                if value_array is not None:
                    for string_val in value_array.findall('.//a:string', NAMESPACES):
                        if string_val.text:
                            values.append(string_val.text)
                
                selected_idx_elem = any_type.find('.//kb:SelectedIndex', NAMESPACES)
                if selected_idx_elem is not None:
                    selected_index = int(selected_idx_elem.text)
            
            prop = PropertyTM7(
                display_name=display_name or '',
                name=name,
                value=value,
                selected_index=selected_index,
                values=values
            )
            properties.append(prop)
        
        return properties
    
    def _parse_threats(self) -> List[ThreatTM7]:
        """Parse todas as ameaças identificadas"""
        threats = []
        threat_instances = self.root.find('.//tm:ThreatInstances', NAMESPACES)
        
        if threat_instances is None:
            return threats
        
        for kv_pair in threat_instances.findall('.//a:KeyValueOfstringThreatpc_P0_PhOB', NAMESPACES):
            threat = self._parse_threat(kv_pair)
            if threat:
                threats.append(threat)
        
        return threats
    
    def _parse_threat(self, kv_elem) -> Optional[ThreatTM7]:
        """Parse uma ameaça individual"""
        value_elem = kv_elem.find('.//a:Value', NAMESPACES)
        if value_elem is None:
            return None
        
        threat_id = self._get_text(kv_elem, './/a:Key', NAMESPACES)
        type_id = self._get_text(value_elem, './/kb:TypeId', NAMESPACES)
        priority = self._get_text(value_elem, './/kb:Priority', NAMESPACES)
        state = self._get_text(value_elem, './/kb:State', NAMESPACES)
        source_guid = self._get_text(value_elem, './/kb:SourceGuid', NAMESPACES)
        target_guid = self._get_text(value_elem, './/kb:TargetGuid', NAMESPACES)
        flow_guid = self._get_text(value_elem, './/kb:FlowGuid', NAMESPACES)
        
        # Parse propriedades da ameaça
        props = value_elem.find('.//kb:Properties', NAMESPACES)
        title = ""
        category = ""
        description = ""
        
        if props is not None:
            for kv in props.findall('.//a:KeyValueOfstringstring', NAMESPACES):
                key = self._get_text(kv, './/a:Key', NAMESPACES)
                val = self._get_text(kv, './/a:Value', NAMESPACES)
                
                if key == 'Title':
                    title = val
                elif key == 'UserThreatCategory':
                    category = val
                elif key == 'UserThreatDescription':
                    description = val
        
        return ThreatTM7(
            threat_id=threat_id,
            type_id=type_id,
            title=title,
            category=category,
            description=description,
            priority=priority,
            state=state,
            source_guid=source_guid,
            target_guid=target_guid,
            flow_guid=flow_guid
        )
    
    def _parse_meta_info(self) -> Dict[str, str]:
        """Parse meta informações do modelo"""
        meta_info = {}
        meta_elem = self.root.find('.//tm:MetaInformation', NAMESPACES)
        
        if meta_elem is not None:
            for child in meta_elem:
                tag = child.tag.split('}')[-1]  # Remove namespace
                meta_info[tag] = child.text or ""
        
        return meta_info
    
    def _get_property_value(self, elem, prop_name: str) -> str:
        """Obtém o valor de uma propriedade específica pelo nome"""
        props_elem = elem.find('.//abs:Properties', NAMESPACES)
        if props_elem is None:
            return ""
        
        for any_type in props_elem.findall('.//a:anyType', NAMESPACES):
            name = self._get_text(any_type, './/kb:Name', NAMESPACES)
            if name == prop_name or (not name and prop_name == 'Name'):
                display_name = self._get_text(any_type, './/kb:DisplayName', NAMESPACES)
                if display_name == prop_name:
                    value = self._get_text(any_type, './/kb:Value', NAMESPACES)
                    return value or ""
        
        return ""
    
    def _get_text(self, elem, xpath: str, namespaces: dict) -> str:
        """Obtém texto de um elemento XML"""
        found = elem.find(xpath, namespaces)
        return found.text if found is not None and found.text else ""
    
    def _get_float(self, elem, xpath: str, namespaces: dict) -> Optional[float]:
        """Obtém valor float de um elemento XML"""
        text = self._get_text(elem, xpath, namespaces)
        try:
            return float(text) if text else None
        except ValueError:
            return None
    
    def _detect_boundary_crossings(self, diagram: DiagramTM7):
        """Detecta quais trust boundaries cada dataflow cruza"""
        # Criar mapa de elementos por GUID
        elements_map = {elem.guid: elem for elem in diagram.elements}
        
        for dataflow in diagram.dataflows:
            # Obter posições dos elementos source e target
            source_elem = elements_map.get(dataflow.source_guid)
            target_elem = elements_map.get(dataflow.target_guid)
            
            if not source_elem or not target_elem:
                continue
            
            # Calcular centro dos elementos
            source_center = self._get_element_center(source_elem)
            target_center = self._get_element_center(target_elem)
            
            # Verificar quais boundaries são cruzadas
            for boundary in diagram.trust_boundaries:
                if self._line_crosses_boundary(source_center, target_center, boundary):
                    dataflow.crossed_boundaries.append(boundary.guid)
    
    def _get_element_center(self, element: ElementTM7) -> tuple:
        """Calcula o centro de um elemento"""
        if element.left is None or element.top is None:
            return (0, 0)
        
        center_x = element.left + (element.width or 0) / 2
        center_y = element.top + (element.height or 0) / 2
        return (center_x, center_y)
    
    def _line_crosses_boundary(self, p1: tuple, p2: tuple, boundary: TrustBoundaryTM7) -> bool:
        """
        Verifica se uma linha entre dois pontos cruza uma boundary.
        Considera que cruza se um ponto está dentro e outro fora da boundary.
        """
        p1_inside = self._point_inside_boundary(p1, boundary)
        p2_inside = self._point_inside_boundary(p2, boundary)
        
        # Cruza se um está dentro e outro fora
        return p1_inside != p2_inside
    
    def _point_inside_boundary(self, point: tuple, boundary: TrustBoundaryTM7) -> bool:
        """Verifica se um ponto está dentro de uma boundary"""
        x, y = point
        
        return (boundary.left <= x <= boundary.left + boundary.width and
                boundary.top <= y <= boundary.top + boundary.height)

def dataflows_to_json(diagram, create_file=False):
    """
    Transforma os dataflows do diagrama em uma lista de dicionários JSON.
    
    Args:
        diagram: Objeto do diagrama contendo dataflows, elementos e trust_boundaries
        
    Returns:
        list: Lista de dicionários com informações dos dataflows
    """
    result = []
    
    # Criar um mapa de guid -> elemento para acesso rápido
    elements_map = {}
    for element in diagram.elements:
        elements_map[element.guid] = element
    
    # Criar um mapa de guid -> trust_boundary para acesso rápido
    boundaries_map = {}
    for tb in diagram.trust_boundaries:
        boundaries_map[tb.guid] = tb
    
    # Processar cada dataflow
    for idx, flow in enumerate(diagram.dataflows, start=1):
        # Buscar elementos de origem e destino
        source_element = elements_map.get(flow.source_guid)
        target_element = elements_map.get(flow.target_guid)
        
        # Criar o dicionário do dataflow
        dataflow_dict = {
            "id": f"DFD-{idx:03d}",
            "source": f"{source_element.name} - ({source_element.type_id})" if source_element else f"Unknown ({flow.source_guid})",
            "target": f"{target_element.name} - ({target_element.type_id})" if target_element else f"Unknown ({flow.target_guid})",
            "data_flow": flow.name,
            "trust_boundaries": {},
        }
        
        # Adicionar trust boundaries se existirem
        if flow.crossed_boundaries:
            trust_boundaries = {}
            for boundary_idx, boundary_guid in enumerate(flow.crossed_boundaries, start=1):
                boundary = boundaries_map.get(boundary_guid)
                if boundary:
                    trust_boundaries[boundary_idx] = boundary.name
            
            
            dataflow_dict["trust_boundaries"] = trust_boundaries
            
        
        result.append(dataflow_dict)
    
    if create_file:
        filename = f"dataflow_{diagram.name}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    return result

def threat_model_to_json(threat_model):
    """
    Converts a threat_model object into a structured JSON representation.
    Expected: threat_model.threats is a list of objects with attributes:
      - category
      - description
      - justification (optional)
    """
    threats_data = []

    for threat in threat_model.threats:
        print(threat)
        threat_entry = {
            "Category": threat.category,
            "Description": threat.description
        }
        threats_data.append(threat_entry)

    result = {
        "threat_model": threats_data
    }    

    # Return the JSON string (pretty-printed)
    return json.dumps(result, indent=2, ensure_ascii=False)

def generate_tmt_dataframe(threat_data):   
                            
    """
    Converts a JSON structure with 'threat_model' key into a DataFrame.
    Removes the 'threat_model' wrapper and normalizes the threat entries.
    """
    # If it's a JSON string, parse it
    if isinstance(threat_data, str):
        json_data = json.loads(threat_data)
    
    # Extract the list inside 'threat_model'
    threat_list = json_data.get("threat_model", [])
    
    # Convert to DataFrame
    df = pd.DataFrame(threat_list)
    
    return df

# Exemplo de uso:
# json_data = dataflows_to_json(diagram)
# import json
# print(json.dumps(json_data, indent=2, ensure_ascii=False))

# Exemplo de uso
if __name__ == "__main__":
    # Carregar arquivo .tm7
    with open('Renato_manager.tm7', 'r', encoding='utf-8') as f:
        xml_content = f.read()
    
    # Parse do arquivo
    parser = TM7Parser(xml_content)
    threat_model = parser.parse()
    
    # Exibir resultados
    print(f"Threat Model Version: {threat_model.version}")
    print(f"\nTotal de Diagramas: {len(threat_model.diagrams)}")
    
    for diagram in threat_model.diagrams:
        print(f"\n--- Diagrama: {diagram.name} ---")
        # print(f"  Qtd Elementos: {len(diagram.elements)}")
        
    #     for elem in diagram.elements:
    #         print(f"    - {elem.name} ({elem.type_id})")
    #         print(f"      GUID: {elem.guid}")
    #         print(f"      Posição: ({elem.left}, {elem.top})")
        
        print(f"\n  Qtd Dataflows: {len(diagram.dataflows)}")
        # for flow in diagram.dataflows:
        #     print(f"    - {flow.name}")
        #     print(f"      De: {flow.source_guid} → Para: {flow.target_guid}")
        #     if flow.crossed_boundaries:
        #         print(f"      Cruza {len(flow.crossed_boundaries)} boundary(ies)")
        #         for boundary_guid in flow.crossed_boundaries:
        #             boundary = next((tb for tb in diagram.trust_boundaries 
        #                            if tb.guid == boundary_guid), None)
        #             if boundary:
        #                 print(f"        • {boundary.name}")
        
        json_data = dataflows_to_json(diagram, create_file=True )
        # print(json.dumps(json_data, indent=2, ensure_ascii=False))
        
        
        
        # print(f"\n  Trust Boundaries: {len(diagram.trust_boundaries)}")
        # for tb in diagram.trust_boundaries:
        #     print(f"    - {tb.name}")
    
    print(f"\n\nTotal de Ameaças: {len(threat_model.threats)}")
    for threat in threat_model.threats:
        print(f"\n  - [{threat.priority}] {threat.title}")
        print(f"    Categoria: {threat.category}")
        print(f"    Estado: {threat.state}")
        print(f"    Descrição: {threat.description[:100]}...")