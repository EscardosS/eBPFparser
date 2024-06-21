#include "parser.h"

int main()
{
    printf("parsing started..\n\n");

    // input your values here

    bpf_insn insns[19]; // [rsp+0h] [rbp-A0h] BYREF

    insns[0].code = 24;
    insns[0].regs = insns[0].regs & 0xF0 | 1;
    insns[0].regs = insns[0].regs & 0xF | 0x10;
    insns[0].off = 0;
    insns[0].imm = small_map;
    insns[1].code = 0;
    insns[1].regs &= 0xF0u;
    insns[1].regs &= 0xFu;
    insns[1].off = 0;
    insns[1].imm = small_map >> 31;
    insns[2].code = -65;
    insns[2].regs = insns[2].regs & 0xF0 | 2;
    insns[2].regs = insns[2].regs & 0xF | 0xA0;
    insns[2].off = 0;
    insns[2].imm = 0;
    insns[3].code = 7;
    insns[3].regs = insns[3].regs & 0xF0 | 2;
    insns[3].regs &= 0xFu;
    insns[3].off = 0;
    insns[3].imm = -4;
    insns[4].code = 98;
    insns[4].regs = insns[4].regs & 0xF0 | 2;
    insns[4].regs &= 0xFu;
    insns[4].off = 0;
    insns[4].imm = 9;
    insns[5].code = -123;
    insns[5].regs &= 0xF0u;
    insns[5].regs &= 0xFu;
    insns[5].off = 0;
    insns[5].imm = 1;
    insns[6].code = -65;
    insns[6].regs = insns[6].regs & 0xF0 | 9;
    insns[6].regs = insns[6].regs & 0xF | 0xA0;
    insns[6].off = 0;
    insns[6].imm = 0;
    insns[7].code = 31;
    insns[7].regs = insns[7].regs & 0xF0 | 9;
    insns[7].regs &= 0xFu;
    insns[7].off = 0;
    insns[7].imm = 0;
    insns[8].code = 24;
    insns[8].regs = insns[8].regs & 0xF0 | 1;
    insns[8].regs = insns[8].regs & 0xF | 0x10;
    insns[8].off = 0;
    insns[8].imm = small_map;
    insns[9].code = 0;
    insns[9].regs &= 0xF0u;
    insns[9].regs &= 0xFu;
    insns[9].off = 0;
    insns[9].imm = insns[1].imm;
    insns[10].code = -65;
    insns[10].regs = insns[10].regs & 0xF0 | 2;
    insns[10].regs = insns[10].regs & 0xF | 0xA0;
    insns[10].off = 0;
    insns[10].imm = 0;
    insns[11].code = 7;
    insns[11].regs = insns[11].regs & 0xF0 | 2;
    insns[11].regs &= 0xFu;
    insns[11].off = 0;
    insns[11].imm = -4;
    insns[12].code = 98;
    insns[12].regs = insns[12].regs & 0xF0 | 2;
    insns[12].regs &= 0xFu;
    insns[12].off = 0;
    insns[12].imm = 0;
    insns[13].code = -123;
    insns[13].regs &= 0xF0u;
    insns[13].regs &= 0xFu;
    insns[13].off = 0;
    insns[13].imm = 1;
    insns[14].code = 85;
    insns[14].regs &= 0xF0u;
    insns[14].regs &= 0xFu;
    insns[14].off = 1;
    insns[14].imm = 0;
    insns[15].code = -107;
    insns[15].regs &= 0xF0u;
    insns[15].regs &= 0xFu;
    insns[15].off = 0;
    insns[15].imm = 0;
    insns[16].code = 123;
    insns[16].regs &= 0xF0u;
    insns[16].regs = insns[16].regs & 0xF | 0x90;
    insns[16].off = 0;
    insns[16].imm = 0;
    insns[17].code = -73;
    insns[17].regs &= 0xF0u;
    insns[17].regs &= 0xFu;
    insns[17].off = 0;
    insns[17].imm = 0;
    insns[18].code = -107;
    insns[18].regs &= 0xF0u;
    insns[18].regs &= 0xFu;
    insns[18].off = 0;
    insns[18].imm = 0;

    for (int i = 0; i < sizeof(insns) / sizeof(bpf_insn); i++)
        parse_code(insns[i]);

    printf("\nparsing complete\n");
    system("pause");
    return 0;
}