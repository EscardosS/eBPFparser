#define REGISTER_FLAG(FLAG) { FLAG, #FLAG }
using flags_str_t = std::map<uint64_t, std::string>;

struct bpf_insn {
	unsigned char code;		/* opcode */
	unsigned char regs;	/* registers */
	short off;		/* signed offset */
	int imm;		/* signed immediate constant */
};

/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC    0x07

#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
#define		BPF_DW		0x18 /* double word (64-bit) */

static const flags_str_t bpf_size =
{
	REGISTER_FLAG(BPF_W),
	REGISTER_FLAG(BPF_H),
	REGISTER_FLAG(BPF_B),
	REGISTER_FLAG(BPF_DW),
};

#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

#define BPF_MEMSX	0x80	/* load with sign extension */
#define BPF_ATOMIC	0xc0	/* atomic memory ops - op type in immediate */
#define BPF_XADD	0xc0	/* exclusive add - legacy name */


/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0


#define BPF_NOSPEC	0xc0
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

static const flags_str_t bpf_opcode =
{
	REGISTER_FLAG(BPF_ADD),
	REGISTER_FLAG(BPF_SUB),
	REGISTER_FLAG(BPF_MUL),
	REGISTER_FLAG(BPF_DIV),
	REGISTER_FLAG(BPF_OR),
	REGISTER_FLAG(BPF_AND),
	REGISTER_FLAG(BPF_LSH),
	REGISTER_FLAG(BPF_RSH),
	REGISTER_FLAG(BPF_NEG),
	REGISTER_FLAG(BPF_MOD),
	REGISTER_FLAG(BPF_XOR),
	REGISTER_FLAG(BPF_MOV),
	REGISTER_FLAG(BPF_NOSPEC),
};

#define BPF_PSEUDO_MAP_FD	1
#define small_map 1
#define big_map 2

static const flags_str_t bpf_maps =
{
	REGISTER_FLAG(small_map),
	REGISTER_FLAG(big_map),
};

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

static const flags_str_t bpf_jmp=
{
	REGISTER_FLAG(BPF_JA),
	REGISTER_FLAG(BPF_JEQ),
	REGISTER_FLAG(BPF_JGT),
	REGISTER_FLAG(BPF_JGE),
	REGISTER_FLAG(BPF_JSET),
	REGISTER_FLAG(BPF_JNE),
	REGISTER_FLAG(BPF_JLE),
	REGISTER_FLAG(BPF_JSGT),
	REGISTER_FLAG(BPF_JSGE),
	REGISTER_FLAG(BPF_JSLT),
	REGISTER_FLAG(BPF_JSLE),
	REGISTER_FLAG(BPF_CALL),
	REGISTER_FLAG(BPF_EXIT),
};


#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

static const flags_str_t bpf_src =
{
	REGISTER_FLAG(BPF_K),
	REGISTER_FLAG(BPF_X),
};

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

/* ArgX, context and stack frame pointer register positions. Note,
 * Arg1, Arg2, Arg3, etc are used as argument mappings of function
 * calls in BPF_CALL instruction.
 */
#define BPF_REG_ARG1	BPF_REG_1
#define BPF_REG_ARG2	BPF_REG_2
#define BPF_REG_ARG3	BPF_REG_3
#define BPF_REG_ARG4	BPF_REG_4
#define BPF_REG_ARG5	BPF_REG_5
#define BPF_REG_CTX	BPF_REG_6
#define BPF_REG_FP	BPF_REG_10

 /* Additional register mappings for converted user programs. */
#define BPF_REG_A	BPF_REG_0
#define BPF_REG_X	BPF_REG_7
#define BPF_REG_TMP	BPF_REG_2	/* scratch reg */
#define BPF_REG_D	BPF_REG_8	/* data, callee-saved */
#define BPF_REG_H	BPF_REG_9	/* hlen, callee-saved */

static const flags_str_t bpf_regs =
{
	REGISTER_FLAG(BPF_REG_ARG1),
	REGISTER_FLAG(BPF_REG_ARG2),
	REGISTER_FLAG(BPF_REG_ARG3),
	REGISTER_FLAG(BPF_REG_ARG4),
	REGISTER_FLAG(BPF_REG_ARG5),
	REGISTER_FLAG(BPF_REG_CTX),
	REGISTER_FLAG(BPF_REG_FP),
	REGISTER_FLAG(BPF_REG_0),
	REGISTER_FLAG(BPF_REG_7),
	REGISTER_FLAG(BPF_REG_2),
	REGISTER_FLAG(BPF_REG_8),
	REGISTER_FLAG(BPF_REG_9),
};

//add functions if needed
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3
#define BPF_FUNC_get_current_comm 16

static const flags_str_t bpf_func =
{
	REGISTER_FLAG(BPF_FUNC_map_lookup_elem),
	REGISTER_FLAG(BPF_FUNC_map_update_elem),
	REGISTER_FLAG(BPF_FUNC_map_delete_elem),
	REGISTER_FLAG(BPF_FUNC_get_current_comm),
};

/* Kernel hidden auxiliary/helper register. */
#define BPF_REG_AX		MAX_BPF_REG
#define MAX_BPF_EXT_REG		(MAX_BPF_REG + 1)
#define MAX_BPF_JIT_REG		MAX_BPF_EXT_REG