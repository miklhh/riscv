use object::{Object, ObjectSegment};
use std::error::Error;
use std::fs;
use std::ops::{Index, IndexMut};

//
// Memory struct
//
struct Memory {
    phy_mem: Vec<u8>,
    offset: usize,
}
impl Index<usize> for Memory {
    type Output = u8;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.phy_mem[idx - self.offset]
    }
}
impl IndexMut<usize> for Memory {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.phy_mem[idx - self.offset]
    }
}
impl Memory {
    fn from_virt(self: &mut Self, addr: usize) -> &mut u8 {
        return &mut self.phy_mem[addr - self.offset];
    }
    fn new(size: usize) -> Memory {
        return Memory { phy_mem: vec![0; size], offset: 0x0 }
    }
    fn dump_stdout(self: &Self) {
        for (i, byte) in self.phy_mem.iter().enumerate() {
            if i % 0x10 == 0 {
                print!("0x{:08x}: ", self.offset+i);
            }
            print!(" {:02x} ", byte);
            if i % 0x10 == 15 {
                println!("");
            }
        }
    }
    fn r32(&self, idx: usize) -> u32 {
        let low_low: u8 = self.phy_mem[idx - self.offset + 0];
        let low_high: u8 = self.phy_mem[idx - self.offset + 1];
        let high_low: u8 = self.phy_mem[idx - self.offset + 2];
        let high_high: u8 = self.phy_mem[idx - self.offset + 3];
        (high_high as u32) << 24 | (high_low as u32) << 16 | (low_high as u32) << 8 | (low_low as u32)
    }
    fn r16(&self, idx: usize) -> u16 {
        let low: u8 = self.phy_mem[idx - self.offset].to_ne_bytes()[0];
        let high: u8 = self.phy_mem[idx - self.offset].to_ne_bytes()[1];
        (high as u16) << 8 | (low as u16)
    }
    fn r8(&self, idx: usize) -> u8 {
        self.phy_mem[idx - self.offset]
    }
    fn s32(&mut self, idx: usize, data: u32) {
        self.phy_mem[idx - self.offset + 0] = data.to_ne_bytes()[0];
        self.phy_mem[idx - self.offset + 1] = data.to_ne_bytes()[1];
        self.phy_mem[idx - self.offset + 2] = data.to_ne_bytes()[2];
        self.phy_mem[idx - self.offset + 3] = data.to_ne_bytes()[3];
    }
    fn s16(&mut self, idx: usize, data: u16) {
        self.phy_mem[idx - self.offset + 0] = data.to_ne_bytes()[0];
        self.phy_mem[idx - self.offset + 1] = data.to_ne_bytes()[1];
    }
    fn s8(&mut self, idx: usize, data: u8) {
        self.phy_mem[idx - self.offset] = data;
    }
}

//
// Register file
//
struct RegFile {
    regs: Vec<u32>,
}
impl Index<usize> for RegFile{
    type Output = u32;
    fn index(&self, index: usize) -> &Self::Output {
        &self.regs[index]
    }
}
impl RegFile {
    fn new() -> RegFile {
        RegFile { regs: vec![0; 32] }
    }
    fn set_reg(&mut self, idx: usize, val: u32) {
        self.regs[idx] = val;
    }
    fn pc(&self) -> u32 {
        self.regs[32]
    }
}

//
// Read ELF from file into memory
//
fn read_elf<const MEM_SIZE: usize>(file_name: &str, memory: &mut Memory) -> Result<(), Box<dyn Error>>{
    // Read ELF from file
    let bin_data = fs::read(file_name)?;
    let obj_file = object::File::parse(&*bin_data)?;

    // Get virtual memory offset which is the address to the first segment in the ELF file
    let offset = obj_file.segments().next().unwrap().address();
    memory.offset = offset as usize;

    // Store all segments into memory
    for segment in obj_file.segments() {
        let seg_addr_start = segment.address() as usize;
        let seg_data = segment.data()?;
        for idx in 0..segment.size() as usize {
            *memory.from_virt(seg_addr_start+idx) = seg_data[idx];
        }
    }
    std::result::Result::Ok(())
}

//
// CPU
//
struct Cpu {
    memory: Memory,
    regfile: RegFile,
}
impl Cpu {
    fn new(mem: Memory) -> Cpu {
        return Cpu { memory: mem, regfile: RegFile::new() }
    }

    fn step(&mut self) -> Option<i64> {
        // (1) Instruction fetch
        let inst = self.memory.r32(self.regfile.pc());

        // (2) Instruction decode
        //let (rd, rs1, rs2, funct3, funct7)

        // (3) Instruction execute

        // (4) Access (?!?!?)

        // (5) Write back
    }
}

fn main() {

    // Memory 8k
    let mut memory = Memory::new(0x2000);

    // Read ELF from file into memory
    let (mut memory, entry_addr) = read_elf("../riscv-tests/isa/rv32ui-p-add", &mut memory).unwrap();

    // Dump memory
    memory.dump_stdout();

    // Create cpu and step through program
    let mut cpu = Cpu::new(memory, entry_addr);
    loop {
        if let Some(res) = cpu.step() {

        }
    }

}

