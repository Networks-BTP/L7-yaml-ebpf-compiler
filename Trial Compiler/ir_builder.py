from dataclasses import dataclass
from typing import List, Optional, Any
from frontend import ProtocolSchema
from semantic import SymbolTable

# --- 1. Base IR Node ---
class IRNode:
    pass

# --- 2. Specific IR Nodes ---
@dataclass
class SetupContextNode(IRNode):
    """Initializes data and data_end pointers."""
    pass

@dataclass
class L2L3L4ParseNode(IRNode):
    """Generates boilerplate for Ethernet -> IP -> UDP/TCP -> Port filtering."""
    transport: str  # 'tcp' or 'udp'
    port: int

@dataclass
class ParseHeaderNode(IRNode):
    """Casts payload to the header struct and bounds checks it."""
    struct_name: str
    ptr_name: str

@dataclass
class PayloadDiscriminatorNode(IRNode):
    """Handles Modbus-style switch cases based on a field value."""
    discriminator_path: str
    cases: dict
    ptr_name: str

@dataclass
class PayloadArrayNode(IRNode):
    """Handles sFlow-style bounded arrays."""
    element_type: str
    length_field_path: str
    max_elements: int
    ptr_name: str

@dataclass
class FilterCheckNode(IRNode):
    """Generates the observability.filters conditions."""
    field_path: str
    op: str
    value: Any

@dataclass
class EmitEventNode(IRNode):
    """Submits parsed data to a ring buffer."""
    event_struct_name: str

# --- 3. The IR Generator Logic ---
def build_ir(schema: ProtocolSchema, sym_tab: SymbolTable) -> List[IRNode]:
    ir_nodes = []

    # 1. Packet Context & Network Layer
    ir_nodes.append(SetupContextNode())
    ir_nodes.append(L2L3L4ParseNode(transport=schema.transport, port=schema.port))

    # 2. Application Header Parsing
    header_struct = schema.layout.header
    ir_nodes.append(ParseHeaderNode(struct_name=header_struct, ptr_name="app_header"))

    # 3. Observability Filters (Evaluated early to save CPU cycles)
    if schema.observability and schema.observability.filters:
        for f in schema.observability.filters:
            ir_nodes.append(FilterCheckNode(field_path=f.field, op=f.op, value=f.value))

    # 4. Payload Parsing (Branching Logic)
    if schema.layout.payload:
        payload = schema.layout.payload
        if payload.discriminator:
            # Modbus TCP style
            ir_nodes.append(PayloadDiscriminatorNode(
                discriminator_path=payload.discriminator,
                cases=payload.cases,
                ptr_name="payload_ptr"
            ))
        elif payload.type == 'array':
            # sFlow V5 style
            ir_nodes.append(PayloadArrayNode(
                element_type=payload.element_type,
                length_field_path=payload.length_field,
                max_elements=payload.max_elements,
                ptr_name="payload_array"
            ))

    # 5. Emit Events (Metrics/Ringbuf)
    # If we made it past all filters and bounds checks, submit the event
    ir_nodes.append(EmitEventNode(event_struct_name=f"{schema.protocol}Event"))

    return ir_nodes

# --- 4. Test Execution ---
if __name__ == "__main__":
    import sys
    from frontend import parse_yaml_spec
    from semantic import build_symbol_table
    
    schema = parse_yaml_spec(sys.argv[1])
    sym_tab = build_symbol_table(schema)
    ir_tree = build_ir(schema, sym_tab)
    
    print("--- Intermediate Representation (Execution Flow) ---")
    for i, node in enumerate(ir_tree):
        print(f"[{i:02d}] {node.__class__.__name__}")
        for k, v in vars(node).items():
            print(f"      - {k}: {v}")