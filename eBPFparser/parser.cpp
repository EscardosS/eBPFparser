#include "parser.h"



std::string parse_enum(uint64_t value, const flags_str_t& enum_map)
{
    auto it = enum_map.find(value);
    if (it != enum_map.end())
        return it->second;
    return std::to_string(value);
}

void parse_ld(bpf_insn val)
{
    if ((val.code & 0x07) == BPF_LD)
    {
        if ((val.code & 0xe0) == BPF_IMM)
        {
            if (val.code)
            {
                if ((val.regs >> 4) == BPF_PSEUDO_MAP_FD)
                    printf("BPF_LD_MAP_FD(%s, %s),\n",
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        parse_enum(val.imm, bpf_maps).c_str());
                else if((val.regs >> 4) == 0)
                    printf("BPF_LD_IMM64(%s, %u),\n",
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        val.imm);
                else
                    printf("BPF_LD_IMM64_RAW(%s, %s, 0x%0.2X),\n",
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        parse_enum(val.regs >> 4, bpf_regs).c_str(),
                        val.imm);
            }
            else
                return;
        }
        else if ((val.code & 0xe0) == BPF_ABS)
        {
            printf("BPF_LD_ABS(%s, %d),\n",
                parse_enum(val.code & 0x18, bpf_size).c_str(),
                val.imm);
        }
        else if ((val.code & 0xe0) == BPF_IND)
        {
            printf("BPF_LD_IND(%s, %d),\n",
                parse_enum(val.code & 0x18, bpf_size).c_str(),
                val.imm);
        }
    }
    else
    {
        if ((val.code & 0xe0) == BPF_MEM)
        {
            printf("BPF_LDX_MEM(%s, %s, %s, %d),\n",
                parse_enum(val.code & 0x18, bpf_size).c_str(),
                parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                parse_enum(val.regs >> 4, bpf_regs).c_str(),
                val.off);
        }
        else if ((val.code & 0xe0) == BPF_MEMSX)
        {
            printf("BPF_LDX_MEMSX(%s, %s, %s, %d),\n",
                parse_enum(val.code & 0x18, bpf_size).c_str(),
                parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                parse_enum(val.regs >> 4, bpf_regs).c_str(),
                val.off);
        }
    }
}

void parse_st(bpf_insn val)
{
    if ((val.code & 0x07) == BPF_ST)
    {
        if ((val.code & 0xe0) == BPF_NOSPEC)
        {
            printf("BPF_ST_NOSPEC(),\n");
        }
        else if ((val.code & 0xe0) == BPF_MEM)
        {
            printf("BPF_ST_MEM(%s, %s, %d, %d),\n",
                parse_enum(val.code & 0x18, bpf_size).c_str(),
                parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                val.off,
                val.imm);
        }
    }
    else
    {
        if ((val.code & 0xe0) == BPF_MEM)
        {
            printf("BPF_STX_MEM(%s, %s, %s, %d),\n",
                parse_enum(val.code & 0x18, bpf_size).c_str(),
                parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                parse_enum(val.regs >> 4, bpf_regs).c_str(),
                val.off);
        }
        else if ((val.code & 0xe0) == BPF_XADD)
        {
            printf("BPF_STX_XADD(%s, %s, %s, %d),\n",
                parse_enum(val.code & 0x18, bpf_size).c_str(),
                parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                parse_enum(val.regs >> 4, bpf_regs).c_str(),
                val.off);
        }
    }
}

void parse_alu(bpf_insn val)
{
    if ((val.code & 0x07) == BPF_ALU)
    {
        if ((val.code & 0x08) == BPF_K)
        {
            if ((val.code & 0xf0) == BPF_MOV)
            {
                printf("BPF_MOV32_IMM(%s, %d),\n", parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                    val.imm);
            }
            else
            {
                if (val.off)
                    printf("BPF_ALU32_IMM_OFF(%s, %s, %d, %d),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        val.imm,
                        val.off);
                else
                    printf("BPF_ALU32_IMM(%s, %s, %d),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        val.imm);
            }
        }
        else if ((val.code & 0x08) == BPF_X)
        {
            if ((val.code & 0xf0) == BPF_MOV)
            {
                printf("BPF_MOV32_REG(%s, %s),\n", parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                    parse_enum(val.regs >> 4, bpf_regs).c_str());
            }
            else
            {
                if (val.off)
                    printf("BPF_ALU32_REG_OFF(%s, %s, %s, %d),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        parse_enum(val.regs >> 4, bpf_regs).c_str(),
                        val.off);
                else
                    printf("BPF_ALU32_REG(%s, %s, %s),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        parse_enum(val.regs >> 4, bpf_regs).c_str());
            }
        }
    }
    else
    {
        if ((val.code & 0x08) == BPF_K)
        {
            if ((val.code & 0xf0) == BPF_MOV)
            {
                printf("BPF_MOV64_IMM(%s, %d),\n", parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                    val.imm);
            }
            else
            {
                if (val.off)
                    printf("BPF_ALU64_IMM_OFF(%s, %s, %d, %d),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        val.imm,
                        val.off);
                else
                    printf("BPF_ALU64_IMM(%s, %s, %d),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        val.imm);
            }
        }
        else if ((val.code & 0x08) == BPF_X)
        {
            if ((val.code & 0xf0) == BPF_MOV)
            {
                printf("BPF_MOV64_REG(%s, %s),\n", parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                    parse_enum(val.regs >> 4, bpf_regs).c_str());
            }
            else
            {
                if (val.off)
                    printf("BPF_ALU64_REG_OFF(%s, %s, %s, %d),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        parse_enum(val.regs >> 4, bpf_regs).c_str(),
                        val.off);
                else
                    printf("BPF_ALU64_REG(%s, %s, %s),\n", parse_enum(val.code & 0xf0, bpf_opcode).c_str(),
                        parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                        parse_enum(val.regs >> 4, bpf_regs).c_str());
            }
        }
    }
    return;
}

void parse_jmp(bpf_insn val)
{
    if ((val.code & 0x08) == BPF_K)
    {
        switch (val.code & 0xf0)
        {
        case BPF_CALL:
            printf("BPF_EMIT_CALL(%s),\n", parse_enum(val.imm, bpf_func).c_str());
            break;
        case BPF_EXIT:
            printf("BPF_EXIT_INSN(),\n");
            break;
        default:
            printf("BPF_JMP_IMM(%s, %s, %d, %d),\n", parse_enum(val.code & 0xf0, bpf_jmp).c_str(),
                parse_enum(val.regs & 0xf, bpf_regs).c_str(),
                val.imm,
                val.off);
        }
    }
    else if ((val.code & 0x08) == BPF_X)
    {
        printf("BPF_JMP_REG(%s, %s, %s, %d),\n", parse_enum(val.code & 0xf0, bpf_jmp).c_str(),
            parse_enum(val.regs & 0xf, bpf_regs).c_str(),
            parse_enum(val.regs >> 4, bpf_regs).c_str(),
            val.off);
    }
    return;
}

void parse_code(bpf_insn val)
{
    switch (val.code & 0x07)
    {
    case BPF_LD:
    case BPF_LDX:
        parse_ld(val);
        break;
    case BPF_ST:
    case BPF_STX:
        parse_st(val);
        break;
    case BPF_ALU:
    case BPF_ALU64:
        parse_alu(val);
        break;
    case BPF_JMP:
        parse_jmp(val);
        break;
    case BPF_RET:
        printf("BPF_RET,\n");
        break;
    }
}