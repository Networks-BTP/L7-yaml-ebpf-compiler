from dataclasses import dataclass, field
from typing import Dict, List, Optional
from frontend import ProtocolSchema, parse_yaml_spec

# --- 1. Domain to C-Type Mappings ---

TYPE_SIZES = {
    'u8': 1, 'u16': 2, 'u32': 4, 'ipv4': 4
}

C_TYPES = {
    'u8': 'uint8_t', 'u16': 'uint16_t', 'u32': 'uint32_t', 'ipv4': 'uint32_t'
}

# eBPF requires network-to-host byte swapping for >1 byte integers
ENDIAN_CONVERSIONS = {
    'u16': 'bpf_ntohs', 'u32': 'bpf_ntohl', 'ipv4': 'bpf_ntohl'
}

# --- 2. Semantic Data Models (The Symbol Table) ---

@dataclass
class ResolvedField:
    name: str
    c_type: str
    size: int
    offset: int
    is_array: bool = False
    array_len: int = 0
    endian_func: Optional[str] = None
    is_padding: bool = False

@dataclass
class ResolvedStruct:
    name: str
    total_size: int
    fields: List[ResolvedField] = field(default_factory=list)

@dataclass
class SymbolTable:
    structs: Dict[str, ResolvedStruct] = field(default_factory=dict)
    
# --- 3. The Analyzer Logic ---

def build_symbol_table(schema: ProtocolSchema) -> SymbolTable:
    sym_tab = SymbolTable()

    for struct_name, struct_def in schema.types.items():
        resolved_struct = ResolvedStruct(name=struct_name, total_size=struct_def.size)
        
        # Sort fields by their declared offset to process them sequentially
        sorted_fields = sorted(struct_def.fields.items(), key=lambda item: item[1].offset)
        
        current_offset = 0
        pad_counter = 0

        for field_name, f_def in sorted_fields:
            # 1. Detect and inject explicit padding if there's a gap
            if f_def.offset > current_offset:
                pad_size = f_def.offset - current_offset
                resolved_struct.fields.append(ResolvedField(
                    name=f_def.offset, # Not used for padding
                    c_type=f"char padding_{pad_counter}[{pad_size}]",
                    size=pad_size,
                    offset=current_offset,
                    is_padding=True
                ))
                pad_counter += 1
                current_offset = f_def.offset
                
            elif f_def.offset < current_offset:
                raise ValueError(f"Memory overlap in {struct_name}: '{field_name}' overlaps previous field.")

            # 2. Resolve Field Size and Types
            is_array = 'array' in f_def.type
            base_type = f_def.type.replace('_array', '')
            
            if base_type not in TYPE_SIZES:
                raise ValueError(f"Unknown primitive type: {base_type}")
                
            element_size = TYPE_SIZES[base_type]
            total_field_size = element_size * f_def.max_elements if is_array else element_size

            # 3. Build Resolved Field
            resolved_struct.fields.append(ResolvedField(
                name=field_name,
                c_type=C_TYPES[base_type],
                size=total_field_size,
                offset=f_def.offset,
                is_array=is_array,
                array_len=f_def.max_elements if is_array else 0,
                endian_func=ENDIAN_CONVERSIONS.get(base_type)
            ))
            
            current_offset += total_field_size

        # 4. Handle trailing padding if struct size is larger than last field
        if current_offset < struct_def.size:
            pad_size = struct_def.size - current_offset
            resolved_struct.fields.append(ResolvedField(
                name=current_offset,
                c_type=f"char padding_{pad_counter}[{pad_size}]",
                size=pad_size,
                offset=current_offset,
                is_padding=True
            ))

        sym_tab.structs[struct_name] = resolved_struct

    return sym_tab

# --- 4. Test Execution ---
if __name__ == "__main__":
    import sys
    
    # Assuming frontend.py is in the same directory
    schema = parse_yaml_spec(sys.argv[1])
    symbol_table = build_symbol_table(schema)
    
    print(f"--- Symbol Table Generated ---")
    for s_name, struct in symbol_table.structs.items():
        print(f"\nStruct: {s_name} (Total Size: {struct.total_size} bytes)")
        for f in struct.fields:
            if f.is_padding:
                print(f"  [Offset {f.offset:02d}] {f.c_type}")
            else:
                array_str = f"[{f.array_len}]" if f.is_array else ""
                endian_str = f" (Needs {f.endian_func})" if f.endian_func else ""
                print(f"  [Offset {f.offset:02d}] {f.c_type} {f.name}{array_str}{endian_str}")