use object::{Object, ObjectSection, ObjectSegment};
use std::error::Error;
use std::fs;

//
// Memory struct
//
struct Memory<const MEM_SIZE: usize> {
    phy_mem: [u8; MEM_SIZE],
    offset: usize,
}
impl<const MEM_SIZE: usize> Memory<MEM_SIZE> {
    fn from_virt(self: &mut Self, addr: usize) -> &mut u8 {
        return &mut self.phy_mem[addr - self.offset];
    }
    fn new() -> Memory<MEM_SIZE> {
        return Memory { phy_mem: [0; MEM_SIZE], offset: 0x0 }
    }
    fn dump_stdout(self: &Self) {
        for i in 0..MEM_SIZE {
            if i % 0x10 == 0 {
                print!("0x{:08x}: ", self.offset+i);
            }
            print!(" {:02x} ", self.phy_mem[i]);
            if i % 0x10 == 15 {
                println!("");
            }
        }
    }
}

//
// Read ELF from file into memory
//
fn read_elf<const MEM_SIZE: usize>(file_name: &str, memory: &mut Memory<MEM_SIZE>) -> Result<(), Box<dyn Error>>{
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

        segment.data()?;
        print!("{:#08x}", segment.address());
        println!(" len: {:#x}", segment.size());
        
    }

    std::result::Result::Ok(())
}

fn main() {

    // Memory
    const MEM_SIZE: usize = 0x2000;
    let mut memory = Memory::<MEM_SIZE>::new();

    // Read ELF from file into memory
    read_elf("../riscv-tests/isa/rv32ui-p-add", &mut memory).unwrap();

    // Dump memory
    memory.dump_stdout();
}
