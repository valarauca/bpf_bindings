//Copyright 2016 William Cody Laeder
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//




//!Simple Bindings to BPF
//!
//!The Berkeley Packet Filter is a simple 3 register RISC-like Virtual Machine.
//!There are 3 registers. PC (Program Counter) Think of this like an instruction
//!pointer. A (Accumulator) this is a general purpose register. X (index) this
//!is a general purpose register. All registers are 32bits wide. There are two
//!general purpose memory locations. P\[\] (The Packet) immutable read only
//!and M\[\] (Scratch Pad) read/write memory for the user to manipulate.
//!This memory is indexed like a byte array. The general notation I will use is
//!P\[INDEX:READ_WIDTH\], this is similiar to the python slice notation. For
//!example A = P\[15:2\] will store 2 bytes (Index 15, and 16) of the packet
//!in the lower two bytes of The Accumulator Register.
//!
//!For a more indepth explaination see: https://www.freebsd.org/cgi/man.cgi?bpf(4)

//These are constants that bpf.h defines
const BPF_LD: u16 = 0x00u16;
const BPF_LDX: u16 = 0x01u16;
const BPF_ST: u16 = 0x02u16;
const BPF_STX: u16 = 0x03u16;
const BPF_ALU: u16 = 0x04u16;
const BPF_JMP: u16 = 0x05u16;
const BPF_RET: u16 = 0x06u16;
const BPF_W: u16 = 0x00u16;
const BPF_H: u16 = 0x08u16;
const BPF_B: u16 = 0x10u16;
const BPF_IMM: u16 = 0x00u16;
const BPF_ABS: u16 = 0x20u16;
const BPF_IND: u16 = 0x40u16;
const BPF_MEM: u16 = 0x60u16;
const BPF_LEN: u16 = 0x80u16;
const BPF_MSH: u16 = 0xa0u16;
const BPF_ADD: u16 = 0x00u16;
const BPF_SUB: u16 = 0x10u16;
const BPF_MUL: u16 = 0x20u16;
const BPF_DIV: u16 = 0x30u16;
const BPF_OR: u16 = 0x40u16;
const BPF_AND: u16 = 0x50u16;
const BPF_LSH: u16 = 0x60u16;
const BPF_RSH: u16 = 0x70u16;
const BPF_NEG: u16 = 0x80u16;
const BPF_JA: u16 = 0x00u16;
const BPF_JEQ: u16 = 0x10u16;
const BPF_JGT: u16 = 0x20u16;
const BPF_JGE: u16 = 0x30u16;
const BPF_K: u16 = 0x00u16;
const BPF_X: u16 = 0x08u16;
const BPF_A: u16 = 0x10u16;
const BPF_TAX: u16 = 0x00u16;
const BPF_TXA: u16 = 0x80u16;
const BPF_MISC: u16 = 0x07u16;
const BPF_JSET: u16 = 0x40u16;



///Berkeley Packet Filter Instruction
///
///This is the general layout of a BPF Instruction. Not all fields are used on
///every instruction. Code defines _what_ the instruction will do. JT and JF
///are used on branching instructions. Jump Forward, Jump Back. They are used
///to manipulate the PC register. K is a data value. It's purpose changes based
///on the code field.
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,Hash)]
#[repr(C)]
pub struct bpf_insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32
}

///Berkeley Packet Filter Program
///
///This is the structure that holds an array of bpf_insn to be handed to the
///kernel for usage in packet filtering. This type is exposed for convience.
///To build a program a user will want to see the bpf_factory
#[repr(C)]
pub struct bpf_program {
    pub bf_len: i32,
    pub bj_insns: *const bpf_insn
}

///Berkeley Packet Filter Program Factory
///
///Used to build BPF programs
///
///      use bpf_bindings::{bpf_insn,bpf_program,
///                         Jmp, LoadA, Ret, SliceSize,
///                         bpf_factory};
///      //This program is compariable to
///      //This filter accepts only IP packets between host 128.3.112.15 and 128.3.112.35
///      // struct bpf_insn insns[] = {
///      //        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
///      //        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 8),
///      //        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
///      //        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,0x8003700f, 0, 2),
///      //        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,30),
///      //        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 4),
///      //        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 3),
///      //        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
///      //        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 1),
///      //        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
///      //        BPF_STMT(BPF_RET+BPF_K,0),
///      //  };
///      //
///      let v: Vec<bpf_insn> = vec![
///
///          //read protocol type
///          LoadA::read_size(SliceSize::HalfWord).packet(12),
///          //assert protocol is IPv4
///          Jmp::new(0,8).eq().constant(4),
///          LoadA::read_size(SliceSize::Word).packet(25),
///          Jmp::new(0,2).eq().constant(0x8003700f),
///          LoadA::read_size(SliceSize::Word).packet(30),
///          Jmp::new(3,4).eq().constant(0x80037023),
///          Jmp::new(0,3).eq().constant(0x80037023),
///          LoadA::read_size(SliceSize::Word).packet(30),
///          Jmp::new(0,1).eq().constant(0x8003700f),
///          Ret::read_constant(0xffffffff),
///          Ret::read_constant(0)
///     ];
///     let program = bpf_factory::from_vec(v).unwrap();
///
#[derive(Clone)]
pub struct bpf_factory {
    data: Vec<bpf_insn>
}
impl bpf_factory {
    ///from vector
    pub fn from_vec(v: Vec<bpf_insn>) -> Option<bpf_program> {
        let x = bpf_factory {
            data: v
        };
        x.to_kernel()
    }
    ///construct a new factory
    pub fn new() -> bpf_factory {
        bpf_factory {
            data: Vec::with_capacity(500)
        }
    }
    ///construct a factory with a specific capacity
    pub fn with_capacity(size: usize) -> bpf_factory {
        bpf_factory {
            data: Vec::with_capacity(size)
        }
    }
    ///Get current length
    pub fn len(&self) -> usize {
        self.data.len()
    }
    ///Add Instruction at end
    pub fn append(&mut self, insn: bpf_insn) {
        self.data.push(insn);
    }
    ///Append many
    pub fn append_many(&mut self, data: Vec<bpf_insn>) {
        self.data.extend_from_slice(data.as_slice());
    }
    ///insert at index 0
    pub fn push(&mut self, insn: bpf_insn) {
        self.data.insert(0,insn)
    }
    ///finds the first occurance of instruction
    pub fn find_insn(&self, insn: bpf_insn) -> Option<usize> {
        for i in self.data.iter().enumerate() {
            if *i.1 == insn {
                return Some(i.0);
            }
        }
        None
    }
    //find instruction at an offset
    pub fn find_insn_offset(&self, offset: usize, insn: bpf_insn) -> Option<usize> {
        for i in self.data.iter().enumerate().skip(offset) {
            if *i.1 == insn {
                return Some(i.0);
            }
        }
        None
    }
    ///insert into specific location
    pub fn insert(&mut self, index: usize, instruction: bpf_insn) {
        self.data.insert(index, instruction);
    }
    ///insert several instructions
    pub fn insert_many(&mut self, offset: usize, insn: Vec<bpf_insn> ) {
        let new_len = insn.len() + self.data.len();
        let mut new_data = Vec::with_capacity(new_len);
        //borrow checker is awesome -_-
        {
            let (ptr_start,ptr_end) = self.data.split_at(offset);
            new_data.extend_from_slice(ptr_start);
            new_data.extend_from_slice(insn.as_slice());
            new_data.extend_from_slice(ptr_end);
        }
        self.data = new_data;
    }
    ///convert to kernel format for ingestion. This returns none if the program
    ///is >= i32::MAX
    pub fn to_kernel(self) -> Option<bpf_program >{
        let len: usize = self.data.len();
        if len >= 2147483647 {
            return None;
        }
        let len: i32 = len as i32;
        Some(bpf_program {
            bf_len: len,
            bj_insns: Box::into_raw(self.data.into_boxed_slice()) as *const bpf_insn
        })
    }
}


///This enum is used to set the size of a read or write. Word reads 32bits, 4 bytes.
///HalfWord reads 16bits, 2 bytes. Byte sets... well 1 byte.
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum SliceSize{
    Word,
    HalfWord,
    Byte
}
impl SliceSize {
    fn to_constant(self) -> u16 {
        match self {
            SliceSize::Word => BPF_W,
            SliceSize::HalfWord => BPF_H,
            SliceSize::Byte => BPF_B
        }
    }
}

///Load Accumulator Register
///
///These functions are use dto load the Accumulator Register (A). Examples:
///
///      use bpf_bindings::{SliceSize,LoadA,bpf_insn};
///
///      //A = 25
///      let a: bpf_insn = LoadA::set(25);
///
///      //A = M[100]
///      let b: bpf_insn = LoadA::memory(100);
///
///      //A = PACKETLEN
///      let c: bpf_insn = LoadA::packet_len();
///
///      //A = P[25:1] read 1 byte at the 25th index (0 based) of the packet
///      let d: bpf_insn = LoadA::read_size(SliceSize::Byte).packet(25);
///
///      //A = P[0+X:1] read 1 byte at the Index Register index of the packet
///      let e: bpf_insn = LoadA::read_size(SliceSize::Byte).packet_index(0);
///
pub struct LoadA {
    data: u16
}
impl LoadA {
    ///Build a new LoadA instruction
    pub fn new() -> LoadA {
        LoadA {
            data: BPF_LD
        }
    }
    ///A = PACKET_LEN
    pub fn packet_len() -> bpf_insn {
        bpf_insn {
            code: BPF_LEN|BPF_LD|BPF_W,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
    ///A = K
    pub fn set(k: u32) -> bpf_insn {
        bpf_insn {
            code: BPF_LD|BPF_IMM,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///A = M\[K\]
    pub fn memory(k: u32) -> bpf_insn {
        bpf_insn {
            code: BPF_LD|BPF_MEM,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///Set read size
    pub fn read_size(s: SliceSize) -> LoadA {
        LoadA {
            data: BPF_LD|s.to_constant(),
        }
    }
    ///A = P\[K:#\] develoepr MUST set read size.
    pub fn packet(self, k: u32) -> bpf_insn {
        let mut x = self;
        x.data |= BPF_ABS;
        bpf_insn {
            code: x.data,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///A = P\[X+K\:#] developer MUST set read size
    pub fn packet_index(self, k: u32) -> bpf_insn {
        let mut x = self;
        x.data |= BPF_IND;
        bpf_insn {
            code: x.data,
            jt: 0,
            jf: 0,
            k: k
        }
    }
}

///Load Index Register
///
///These are function that will load the Index Register. Examples:
///
///      use bpf_bindings::{LoadX, SliceSize, bpf_insn};
///
///      //X = 12, set Index Register to 12
///      let a: bpf_insn = LoadX::set(12);
///
///      //X = LEN, set Index Register to PACKET_LEN
///      let b: bpf_insn = LoadX::packet_len();
///
///      //X = M[15:1], set Index Register to index 15 byte in scratch memory
///      let c: bpf_insn = LoadX::read_size(SliceSize::Byte).read(15);
///
///      //X = IPHeaderLength
///      let d: bpf_insn = LoadX::ip_header_len(0);
///
pub struct LoadX {
    data: u16
}
impl LoadX {
    ///Set read size
    pub fn read_size(s: SliceSize) -> LoadX {
        LoadX {
            data: BPF_LDX | s.to_constant()
        }
    }
    ///X = M\[K:#\] MUST set read_size
    pub fn read(self,k: u32) -> bpf_insn {
        let mut x = self;
        x.data |= BPF_MEM;
        bpf_insn {
            code: x.data,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///X = K
    pub fn set(k: u32) -> bpf_insn {
        bpf_insn {
            code: BPF_LDX|BPF_W|BPF_IMM,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///X = LEN
    pub fn packet_len() -> bpf_insn {
        bpf_insn {
            code: BPF_LDX|BPF_W|BPF_LEN,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
    ///X = IP Header Length (where the field starts at K)
    pub fn ip_header_len(k: u32) -> bpf_insn {
        bpf_insn {
            code: BPF_B|BPF_MSH|BPF_LDX,
            jt: 0,
            jf: 0,
            k: k
        }
    }
}

///Store Register
///
///This structure is used to store a register's value into a constant location
///of scratch memory.
///
///Example:
///
///       use bpf_bindings::{StoreReg, bpf_insn};
///
///       //M[10] = A
///       let a: bpf_insn = StoreReg::a().location(10);
///
///       //M[200] = X
///       let b: bpf_insn = StoreReg::x().location(200);
///
pub struct StoreReg {
    data: u16
}
impl StoreReg {
    ///Store A
    pub fn a() -> StoreReg {
        StoreReg {
            data: BPF_ST
        }
    }
    ///Store X
    pub fn x() -> StoreReg {
        StoreReg {
            data: BPF_STX
        }
    }
    ///M[K] = A|X
    pub fn location(self, k: u32) -> bpf_insn {
        bpf_insn {
            code: self.data,
            jt: 0,
            jf: 0,
            k: k
        }
    }
}

///ALU Commands.
///
///Result is always Assigned to A. Each ALU instruction can only
///perform 1 operation (ADD (+), MUL (*), SUB (-), DIV (/), AND (&), OR (|), LeftShift (<<), RightShift (>>)). The API will not throw an error if the user chains
///mutiple values, but the kernel will.
///
///A simple example is:
///
///      use bpf_bindings::{Alu, bpf_insn};
///
///      //A = A + K
///      let x: bpf_insn = Alu::add().constant(5);
///
///      //A = A | X (bitwise)
///      let y: bpf_insn = Alu::or().x_reg();
///
///The API always starts by declaring the operation. Then the developer will
///state where the operand will come from, be it X or K.
pub struct Alu {
    data: u16
}
impl Alu {
    ///Start an ADD Instruction
    pub fn add() -> Alu {
        Alu {
            data: BPF_ALU|BPF_ADD
        }
    }
    ///Start a MUL Instruction
    pub fn mul() -> Alu {
        Alu {
            data: BPF_ALU|BPF_MUL
        }
    }
    ///Start a SUB Instruction
    pub fn sub() -> Alu {
        Alu {
            data: BPF_ALU|BPF_SUB
        }
    }
    ///Start a DIV Instruction
    pub fn div() -> Alu {
        Alu {
            data: BPF_ALU|BPF_DIV
        }
    }
    ///Start an AND Instruction
    pub fn and() -> Alu {
        Alu {
            data: BPF_ALU|BPF_AND
        }
    }
    ///Start an OR Instruction
    pub fn or() -> Alu {
        Alu {
            data: BPF_ALU|BPF_OR
        }
    }
    ///Start a LeftShift Instruction
    pub fn sl() -> Alu {
        Alu {
            data: BPF_ALU|BPF_LSH
        }
    }
    ///Start a RightShift Instruction
    pub fn sr() -> Alu {
        Alu {
            data: BPF_ALU|BPF_RSH
        }
    }
    ///A = -A The Not Instruction
    pub fn not() -> bpf_insn {
        bpf_insn {
            code: BPF_ALU|BPF_NEG,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
    ///Do the operation against a constant
    pub fn constant(self, k: u32) -> bpf_insn {
        let mut x = self;
        x.data |= BPF_K;
        bpf_insn {
            code: x.data,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///Do the operation against reg X (Index Register)
    pub fn x_reg(self) -> bpf_insn {
        let mut x = self;
        x.data |= BPF_X;
        bpf_insn {
            code: x.data,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
}

///Jump Instructions
///
///These are instruction that modify the PC register. They allow for the
///developer to control the flow of their program. On declaration the
///developer will need to state the True And False jump values. All conditionals
///use unsigned convention. Programs may only advance, not back track.
///The system MUST exit.
///
///All Jump Instructions use reg A (Accumulator) as their base for comparisons.
///This means the deverlop is either comparing A to X or A to K.
///
///The allowed Comparison operations are Equal (==), And (&), GT (>), GTE (>=).
///Only one comparison operator is allows per instruction.
///
///Some Examples:
///
///      use bpf_bindings::{Jmp,bpf_insn};
///
///      // PC += 10
///      let a: bpf_insn = Jmp::constant_jmp(10);
///
///      //PC += if A == 82 { 10 } else { 100 };
///      let b: bpf_insn = Jmp::new(10,100).eq().constant(82);
///
///      //PC += if A & X { 12 } else { 16 };
///      let c: bpf_insn = Jmp::new(12,16).and().reg_x();
///
pub struct Jmp {
    data: u16,
    jt: u8,
    jf: u8
}
impl Jmp {
    ///PC += K
    pub fn constant_jmp(k: u32) -> bpf_insn {
        bpf_insn {
            code: BPF_JMP|BPF_JA,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///Build a new jump
    pub fn new(jt: u8, jf: u8) -> Jmp {
        Jmp {
            data: BPF_JMP,
            jt: jt,
            jf: jf
        }
    }
    ///Compare EQ
    pub fn eq(self) -> Jmp {
        let mut x = self;
        x.data |= BPF_JEQ;
        x
    }
    ///Compare AND
    pub fn and(self) -> Jmp {
        let mut x = self;
        x.data |= BPF_JSET;
        x
    }
    ///Compare GT
    pub fn gt(self) -> Jmp {
        let mut x = self;
        x.data |= BPF_JGT;
        x
    }
    ///Compare GTE
    pub fn gte(self) -> Jmp {
        let mut x = self;
        x.data |= BPF_JGE;
        x
    }
    ///Against a constant
    pub fn constant(self, k: u32) -> bpf_insn {
        bpf_insn {
            code: self.data | BPF_K,
            jt: self.jt,
            jf: self.jf,
            k: k
        }
    }
    ///Against reg X (index register)
    pub fn reg_x(self) -> bpf_insn {
        bpf_insn {
            code: self.data | BPF_X,
            jt: self.jt,
            jf: self.jf,
            k: 0
        }
    }
}

///Exit Program
///
///Object that dictates how a packet is read into the computer. This allows for
///the developer to trim the length of a packet, or reject a packet.
///
///       use bpf_bindings::Ret;
///
///       //reject the packet (server will never see packet arrive)
///       let x = Ret::reject();
///
///       //trim packet to a constant length (server will see a packet K size)
///       let y = Ret::read_constant(1000);
///
///       //trim packet to a constant length, or reject it. Depends on A contents
///       let z = Ret::read_a();
pub struct Ret;
impl Ret {
    ///This will accept the packet. Really it is telling the kernel to accept
    ///~3.6GB length packet. So the kernel will just accept the whole packet.
    pub fn accept() -> bpf_insn {
        bpf_insn {
            code: BPF_RET|BPF_K,
            jt: 0,
            jf: 0,
            k: std::u32::MAX
        }
    }
    ///This is reject the packet
    pub fn reject() -> bpf_insn {
        bpf_insn {
            code: BPF_RET|BPF_K,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
    ///Trim the packet to a constant length
    pub fn read_constant(k: u32) -> bpf_insn {
        bpf_insn {
            code: BPF_RET|BPF_K,
            jt: 0,
            jf: 0,
            k: k
        }
    }
    ///Trim the packet to a length determined by A. Note that if A == 0 then the
    ///packet will be rejected
    pub fn read_a() -> bpf_insn {
        bpf_insn {
            code: BPF_RET|BPF_A,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
}

///Copy Reg
///
///Copy a register to another register
pub struct CopyReg;
impl CopyReg {
    ///X = A, A is not modified
    pub fn co_a_to_x() -> bpf_insn {
        bpf_insn {
            code: BPF_MISC|BPF_TAX,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
    ///A = X, X is not modified
    pub fn copy_x_to_a() -> bpf_insn {
        bpf_insn {
            code: BPF_MISC|BPF_TXA,
            jt: 0,
            jf: 0,
            k: 0
        }
    }
}
