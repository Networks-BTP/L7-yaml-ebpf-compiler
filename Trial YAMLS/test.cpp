struct A{
    char padding1[5];
    uint16_t ethernet_header; // We want only these
    char padding2[2];
    uint64_t ip_header; // We want only these
};