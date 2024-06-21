#include <map>
#include <string>
#include "ebpf.h"


std::string parse_enum(uint64_t value, const flags_str_t& enum_map);

void parse_code(bpf_insn val);
