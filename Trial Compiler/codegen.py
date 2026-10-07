import jinja2
from frontend import ProtocolSchema, parse_yaml_spec
from semantic import SymbolTable, build_symbol_table
from ir_builder import build_ir, SetupContextNode, L2L3L4ParseNode, ParseHeaderNode, FilterCheckNode, PayloadDiscriminatorNode, PayloadArrayNode, EmitEventNode

# --- 1. Jinja2 Templates ---

TEMPLATE_COMMON_H = """
#ifndef {{ protocol | upper }}_COMMON_H
#define {{ protocol | upper }}_COMMON_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

{% for struct_name, struct_def in sym_tab.structs.items() %}
// Size: {{ struct_def.total_size }} bytes
struct {{ struct_name }} {
{%- for field in struct_def.fields %}
    {{ field.c_type }}{% if not field.is_padding %} {{ field.name }}{% if field.is_array %}[{{ field.array_len }}]{% endif %}{% endif %};
{%- endfor %}
} __attribute__((packed));

{% endfor %}
#endif
"""

TEMPLATE_XDP_H = """
#ifndef {{ protocol | upper }}_XDP_H
#define {{ protocol | upper }}_XDP_H

#include "common.h"

// Telemetry Event Structure sent to Userspace
struct {{ protocol }}Event {
    __u64 timestamp;
    // Generated fields based on schema parsing capabilities
    // (In a full compiler, this would be dynamically extracted from the AST)
    __u32 filter_matched; 
};

// Ring buffer for passing Event struct from kernel to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

#endif
"""

TEMPLATE_TRACER_BPF_C = """
#include "xdp.h"
#include <linux/pkt_cls.h>

SEC("xdp")
int xdp_{{ protocol | lower }}_parser(struct xdp_md *ctx)
{
{%- for node in ir_nodes %}
    {%- if node.__class__.__name__ == 'SetupContextNode' %}
    // --- 1. Setup Context ---
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    {%- elif node.__class__.__name__ == 'L2L3L4ParseNode' %}

    // --- 2. L2/L3/L4 Parsing ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != {% if node.transport == 'tcp' %}IPPROTO_TCP{% else %}IPPROTO_UDP{% endif %})
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    {%- if node.transport == 'tcp' %}
    struct tcphdr *l4 = (void *)ip + ip_hdr_len;
    if ((void *)(l4 + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(l4->source) != {{ node.port }} && bpf_ntohs(l4->dest) != {{ node.port }})
        return XDP_PASS;
    void *app_payload = (void *)l4 + (l4->doff * 4);
    {%- else %}
    struct udphdr *l4 = (void *)ip + ip_hdr_len;
    if ((void *)(l4 + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(l4->source) != {{ node.port }} && bpf_ntohs(l4->dest) != {{ node.port }})
        return XDP_PASS;
    void *app_payload = (void *)(l4 + 1);
    {%- endif %}
    {%- elif node.__class__.__name__ == 'ParseHeaderNode' %}

    // --- 3. App Header Bounds Check ---
    struct {{ node.struct_name }} *{{ node.ptr_name }} = app_payload;
    if ((void *)({{ node.ptr_name }} + 1) > data_end)
        return XDP_PASS;
    {%- elif node.__class__.__name__ == 'FilterCheckNode' %}

    // --- 4. Observability Filters ---
    // Note: Assuming string IPs are converted to integers in a real pass
    if ({{ node.field_path | replace('.', '->') }} {% if node.op == 'EQUAL' %}!={% endif %} {{ node.value }})
        return XDP_PASS;
    {%- elif node.__class__.__name__ == 'PayloadDiscriminatorNode' %}

    // --- 5. Discriminator Branching ---
    void *{{ node.ptr_name }} = (void *)({{ node.ptr_name | replace('_ptr', '_header') }} + 1); // rough approximation
    __u8 discriminator_val = {{ node.discriminator_path | replace('.', '->') }};
    
    switch(discriminator_val) {
        {%- for key, struct_val in node.cases.items() %}
        case {{ key }}: {
            struct {{ struct_val }} *payload = {{ node.ptr_name }};
            if ((void *)(payload + 1) > data_end) return XDP_PASS;
            break;
        }
        {%- endfor %}
    }
    {%- elif node.__class__.__name__ == 'PayloadArrayNode' %}

    // --- 5. Bounded Array Iteration ---
    struct {{ node.element_type }} *{{ node.ptr_name }} = (void *)(app_header + 1);
    __u32 loop_limit = {{ node.length_field_path | replace('.', '->') }};
    if (loop_limit > {{ node.max_elements }}) loop_limit = {{ node.max_elements }};

    #pragma unroll
    for (int i = 0; i < {{ node.max_elements }}; i++) {
        if (i >= loop_limit) break;
        if ((void *)(&{{ node.ptr_name }}[i] + 1) > data_end) break;
        // Logic to process array element...
    }
    {%- elif node.__class__.__name__ == 'EmitEventNode' %}

    // --- 6. Telemetry Emission ---
    struct {{ node.event_struct_name }} *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->filter_matched = 1;
        bpf_ringbuf_submit(event, 0);
    }
    {%- endif %}
{%- endfor %}

    return XDP_PASS;
}
"""

# --- 2. The Code Generator Function ---

def generate_c_code(schema: ProtocolSchema, sym_tab: SymbolTable, ir_nodes: list):
    env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)

    common_h = env.from_string(TEMPLATE_COMMON_H).render(
        protocol=schema.protocol, sym_tab=sym_tab
    )
    
    xdp_h = env.from_string(TEMPLATE_XDP_H).render(
        protocol=schema.protocol
    )
    
    tracer_c = env.from_string(TEMPLATE_TRACER_BPF_C).render(
        protocol=schema.protocol, ir_nodes=ir_nodes
    )
    
    return common_h, xdp_h, tracer_c

# --- 3. Test Execution ---
if __name__ == "__main__":
    import sys
    
    schema = parse_yaml_spec(sys.argv[1])
    sym_tab = build_symbol_table(schema)
    ir_nodes = build_ir(schema, sym_tab)
    
    common_h, xdp_h, tracer_c = generate_c_code(schema, sym_tab, ir_nodes)
    
    print("================ common.h ================")
    print(common_h)
    print("================ xdp.h ================")
    print(xdp_h)
    print("================ tracer.bpf.c ================")
    print(tracer_c)