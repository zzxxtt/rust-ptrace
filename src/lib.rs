#![feature(step_by)]

extern crate libc;
pub extern crate nix;

use nix::sys::ptrace;
pub use nix::sys::ptrace::ptrace::*;
use nix::sys::signal;
use std::ptr;
use std::default::Default;
use std::vec::Vec;
use std::mem;

pub type Address = usize;
pub type Word = usize;
pub type IWord = isize;

pub const PTRACE_O_EXITKILL: PtraceOptions        = 1 << 20;
pub const PTRACE_O_SUSPEND_SECCOMP: PtraceOptions = 1 << 21;

#[derive(Clone, Copy, Default, Debug)]
pub struct Registers {
    pub r15: Word,
    pub r14: Word,
    pub r13: Word,
    pub r12: Word,
    pub rbp: Word,
    pub rbx: Word,
    pub r11: Word,
    pub r10: Word,
    pub r9: Word,
    pub r8: Word,
    pub rax: Word,
    pub rcx: Word,
    pub rdx: Word,
    pub rsi: Word,
    pub rdi: Word,
    pub orig_rax: Word,
    pub rip: Word,
    pub cs: Word,
    pub eflags: Word,
    pub rsp: Word,
    pub ss: Word,
    pub fs_base: Word,
    pub gs_base: Word,
    pub ds: Word,
    pub es: Word,
    pub fs: Word,
    pub gs: Word
}

fn ptrace_raw(request: PtraceRequest, pid: libc::pid_t, addr: *mut libc::c_void, data: *mut libc::c_void) -> Result<libc::c_long, i32> {
    match ptrace::ptrace(request, pid, addr, data) {
        Ok(v) => Ok(v),
        Err(e) => match e {
            nix::Error::Sys(errno) => Err(errno as i32),
            nix::Error::InvalidPath => panic!("nix InvalidPath caught"),
        },
    }
}
pub fn setoptions(pid: libc::pid_t, options: PtraceOptions) -> Result<(), i32> {
    match ptrace::ptrace_setoptions(pid, options) {
        Ok(v) => Ok(v),
        Err(e) => match e {
            nix::Error::Sys(errno) => Err(errno as i32),
            nix::Error::InvalidPath => panic!("nix InvalidPath caught"),
        },
    }
}

pub fn getregs(pid: libc::pid_t) -> Result<Registers, i32> {
    let mut buf: Registers = Default::default();
    let buf_mut: *mut Registers = &mut buf;

    match ptrace_raw(PTRACE_GETREGS, pid, ptr::null_mut(), buf_mut as *mut libc::c_void) {
        Ok(_) => Ok(buf),
        Err(e) => Err(e)
    }
}

pub fn setregs(pid: libc::pid_t, regs: &Registers) -> Result<libc::c_long, i32> {
    let buf: *mut libc::c_void = unsafe { mem::transmute(regs) };
    ptrace_raw(PTRACE_SETREGS, pid, ptr::null_mut(), buf)
}

pub fn seize(pid: libc::pid_t) -> Result<libc::c_long, i32> {
    ptrace_raw(PTRACE_SEIZE, pid, ptr::null_mut(), ptr::null_mut())
}

pub fn attach(pid: libc::pid_t) -> Result<libc::c_long, i32> {
    ptrace_raw(PTRACE_ATTACH, pid, ptr::null_mut(), ptr::null_mut())
}

pub fn release(pid: libc::pid_t, signal: Option<signal::Signal>) -> Result<libc::c_long, i32> {
    ptrace_raw(PTRACE_DETACH, pid, ptr::null_mut(), signal.map_or(0, |s| s as u32) as *mut libc::c_void)
}

pub fn geteventmsg(pid: libc::pid_t) -> Result<libc::c_ulong, i32> {
    let mut msg: libc::c_ulong = 0;
    let msg_ptr = &mut msg as *mut libc::c_ulong as *mut libc::c_void;
    ptrace_raw(PTRACE_GETEVENTMSG, pid, ptr::null_mut(), msg_ptr)?;
    Ok(msg)
}

pub fn cont(pid: libc::pid_t, signal: Option<signal::Signal>) -> Result<libc::c_long, i32> {
    ptrace_raw(PTRACE_CONT, pid, ptr::null_mut(), signal.map_or(0, |s| s as u32) as *mut libc::c_void)
}

pub fn cont_syscall(pid: libc::pid_t, signal: Option<signal::Signal>) -> Result<libc::c_long, i32> {
    ptrace_raw(PTRACE_SYSCALL, pid, ptr::null_mut(), signal.map_or(0, |s| s as u32) as *mut libc::c_void)
}

pub fn traceme() -> Result<libc::c_long, i32> {
    ptrace_raw(PTRACE_TRACEME, 0, ptr::null_mut(), ptr::null_mut())
}

#[derive(Clone, Copy, Debug)]
pub struct Syscall {
    pub args: [Word; 6],
    pub call: Word,
    pub pid: libc::pid_t,
    pub return_val: IWord
}

impl Syscall {
    pub fn from_pid(pid: libc::pid_t) -> Result<Syscall, i32> {
        match getregs(pid) {
            Ok(regs) =>
                Ok(Syscall {
                    pid: pid,
                    call: regs.orig_rax,
                    args: [regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9],
                    return_val: regs.rax as IWord
                }),
            Err(e) => Err(e)
        }
    }

    pub fn write(&self) -> Result<libc::c_long, i32> {
        match getregs(self.pid) {
            Ok(mut regs) => {
                regs.rdi = self.args[0];
                regs.rsi = self.args[1];
                regs.rdx = self.args[2];
                regs.rcx = self.args[3];
                regs.r8 = self.args[4];
                regs.r9 = self.args[5];
                regs.orig_rax = self.call;
                regs.rax = self.return_val as Word;
                setregs(self.pid, &regs)
            },
            Err(e) => Err(e)
        }
    }
}

#[derive(Clone, Copy)]
pub struct Reader {
    pub pid: libc::pid_t
}

#[derive(Clone, Copy)]
pub struct Writer {
    pub pid: libc::pid_t
}

impl Writer {
    pub fn new(pid: libc::pid_t) -> Self {
        Writer {
            pid: pid
        }
    }

    pub fn poke_data(&self, address: Address, data: Word) -> Result<Word, i32> {
        match ptrace_raw(PTRACE_POKEDATA, self.pid, address as *mut libc::c_void,
                             data as *mut libc::c_void) {
            Err(e) => Err(e),
            Ok(r) => Ok(r as Word)
        }
    }

    pub fn write_object<T: Sized>(&self, address: Address, data: &T) -> Result<(), usize> {
        let mut buf = Vec::with_capacity(mem::size_of::<T>());
        unsafe {
            let tptr: *const T = data;
            let p: *const u8 = mem::transmute(tptr);
            for i in 0..buf.capacity() {
                buf.push(*p.offset(i as isize));
            }
        }

        Ok(())
    }

    pub fn write_data(&self, address: Address, buf: &Vec<u8>) -> Result<(), i32> {
        // The end of our range
        let max_addr = address + buf.len() as Address;
        // The last word we can completely overwrite
        let align_end = max_addr - (max_addr % mem::size_of::<Word>() as Address);
        for write_addr in (address..align_end).step_by(mem::size_of::<Word>() as Address) {
            let mut d: Word = 0;
            let buf_idx = (write_addr - address) as usize;
            for word_idx in 0..mem::size_of::<Word>() {
                d = set_byte(d, word_idx, buf[buf_idx + word_idx]);
            }
            match self.poke_data(write_addr, d) {
                Ok(_) => {},
                Err(e) => return Err(e)
            }
        }
        // Handle a partial word overwrite
        if max_addr > align_end {
            let buf_start = buf.len() - (max_addr - align_end) as usize;
            let r = Reader::new(self.pid);
            let mut d = match r.peek_data(align_end) {
                Ok(v) => v,
                Err(e) => return Err(e)
            };
            for word_idx in 0..mem::size_of::<Word>() - 2 {
                let buf_idx = buf_start + word_idx;
                d = set_byte(d, word_idx, buf[buf_idx]);
            }
            match self.poke_data(align_end, d) {
                Ok(_) => {},
                Err(e) => return Err(e)
            }
        }
        Ok(())
    }
}

impl Reader {
    pub fn new(pid: libc::pid_t) -> Reader {
        Reader {
            pid: pid
        }
    }

    pub fn peek_data(&self, address: Address) -> Result<Word, i32> {
        match ptrace_raw(PTRACE_PEEKDATA, self.pid, address as *mut libc::c_void, ptr::null_mut()) {
            Ok(v) => Ok(v as Word),
            Err(e) => Err(e),
        }
    }

    pub fn read_string(&self, address: Address, max_length: usize) -> Result<Vec<u8>, i32> {
        let mut end_of_str = false;
        let mut buf: Vec<u8> = Vec::with_capacity(max_length);
        let max_addr = address + buf.capacity() as Address;
        let align_end = max_addr - (max_addr % mem::size_of::<Word>() as Address);
        'finish: for read_addr in (address..align_end).step_by(mem::size_of::<Word>() as Address) {
            let d;
            match self.peek_data(read_addr) {
                Ok(v) => d = v,
                Err(e) => return Err(e)
            }
            for word_idx in 0..mem::size_of::<Word>() {
                let chr = get_byte(d, word_idx);
                if chr == 0 {
                    end_of_str = true;
                    break 'finish;
                }
                buf.push(chr);
            }
        }
        if !end_of_str {
            let d;
            match self.peek_data(align_end) {
                Ok(v) => d = v,
                Err(e) => return Err(e)
            }
            for word_idx in 0..mem::size_of::<Word>() {
                let chr = get_byte(d, word_idx);
                if chr == 0 {
                    break;
                }
                buf.push(chr);
            }
        }
        return Ok(buf);
    }
}

fn get_byte(d: Word, byte_idx: usize) -> u8 {
    assert!(byte_idx < mem::size_of::<Word>());
    ((d >> (byte_idx * 8)) & 0xff) as u8
}

fn set_byte(d: Word, byte_idx: usize, value: u8) -> Word {
    assert!(byte_idx < mem::size_of::<Word>());
    let shift = mem::size_of::<u8>() * 8 * byte_idx;
    let mask = 0xff << shift;
    (d & !mask) | (((value as Word) << shift) & mask)
}

#[test]
pub fn test_set_byte() {
    assert_eq!(set_byte(0, 0, 0), 0);
    assert_eq!(set_byte(0xffffffffffff, 0, 0xff), 0xffffffffffff);
    assert_eq!(set_byte(0xffffffffffff, 0, 0),    0xffffffffff00);
    assert_eq!(set_byte(0xffffffffffff, 0, 0xaa), 0xffffffffffaa);
    assert_eq!(set_byte(0xffffffffffff, 1, 0x00), 0xffffffff00ff);
    assert_eq!(set_byte(0xffffffffffff, 4, 0xaa), 0xffaaffffffff);
}

#[test]
pub fn test_get_byte() {
    assert_eq!(get_byte(0, 0), 0);
    assert_eq!(get_byte(0xffffffffffff, 0), 0xff);
    assert_eq!(get_byte(0xffffffffffaa, 0), 0xaa);
    assert_eq!(get_byte(0x0123456789ab, 1), 0x89);
    assert_eq!(get_byte(0x0123456789ab, 4), 0x23);
}
