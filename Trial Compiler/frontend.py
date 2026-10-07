import yaml
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator, model_validator

# --- 1. Type Definitions ---

class FieldDef(BaseModel):
    offset: int
    type: str  # e.g., 'u8', 'u16', 'u32', 'ipv4', 'u16_array'
    element_size: Optional[int] = None
    max_elements: Optional[int] = None

    @model_validator(mode='after')
    def validate_array_fields(self):
        # Enforce that array types must define bounded limits for the eBPF verifier
        if 'array' in self.type and self.max_elements is None:
            raise ValueError(f"Array type '{self.type}' must define 'max_elements' for eBPF verifier safety.")
        return self

class StructDef(BaseModel):
    size: int
    fields: Dict[str, FieldDef]

# --- 2. Layout & Payload Definitions ---

class PayloadDef(BaseModel):
    # For discriminator-based payloads (like Modbus)
    discriminator: Optional[str] = None
    cases: Optional[Dict[str, str]] = None  # e.g., {"0x03": "ReadHoldingRegistersResp"}
    
    # For array-based payloads (like sFlow)
    type: Optional[str] = None
    element_type: Optional[str] = None
    length_field: Optional[str] = None
    max_elements: Optional[int] = None

class LayoutDef(BaseModel):
    header: str
    payload: Optional[PayloadDef] = None

# --- 3. Observability Definitions ---

class FilterDef(BaseModel):
    field: str
    op: str # EQUAL, NOT_EQUAL, GREATER_THAN, etc.
    value: Any

class MetricDef(BaseModel):
    field: str

class ObservabilityDef(BaseModel):
    filters: Optional[List[FilterDef]] = Field(default_factory=list)
    metrics: Optional[List[MetricDef]] = Field(default_factory=list)

# --- 4. Root Protocol Schema ---

class ProtocolSchema(BaseModel):
    protocol: str
    transport: str
    port: int
    types: Dict[str, StructDef]
    layout: LayoutDef
    observability: Optional[ObservabilityDef] = None

    @field_validator('transport')
    @classmethod
    def validate_transport(cls, v: str) -> str:
        valid_transports = ['tcp', 'udp']
        if v.lower() not in valid_transports:
            raise ValueError(f"Transport must be one of {valid_transports}")
        return v.lower()

# --- 5. The Parser Function ---

def parse_yaml_spec(file_path: str) -> ProtocolSchema:
    """Reads a YAML file and parses it into strongly-typed Pydantic objects."""
    with open(file_path, 'r') as f:
        raw_data = yaml.safe_load(f)
    
    # This automatically validates the data against the schema
    # If the YAML is malformed, it throws a descriptive ValidationError
    return ProtocolSchema(**raw_data)

# --- 6. Test Execution ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python frontend.py <protocol.yaml>")
        sys.exit(1)
        
    try:
        spec = parse_yaml_spec(sys.argv[1])
        print(f"✅ Successfully parsed specification for: {spec.protocol}")
        print(f"Transport: {spec.transport.upper()} / Port: {spec.port}")
        print(f"Registered Types: {list(spec.types.keys())}")
        
        if spec.layout.payload and spec.layout.payload.cases:
            print(f"Payload Discriminator: {spec.layout.payload.discriminator}")
            
    except Exception as e:
        print(f"❌ Compilation Failed during Frontend parsing:\n{e}")