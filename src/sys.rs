#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use nix::libc;
use nix::{ioctl_read, ioctl_readwrite};
use std::mem::size_of;

pub const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
pub const SECCOMP_GET_NOTIF_SIZES: libc::c_ulong = 3;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;

pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

pub const BPF_LD: u16 = 0x00;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;

pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;

pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_K: u16 = 0x00;

pub const AUDIT_ARCH_X86_64: u32 = 62 | 0x80000000 | 0x40000000;
pub const X32_SYSCALL_BIT: u32 = 0x40000000;

#[repr(C)]
pub struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

pub const fn BPF_STMT(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

pub const fn BPF_JUMP(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

#[repr(C)]
pub struct sock_fprog {
    pub len: libc::c_ushort,
    pub filter: *const sock_filter,
}

pub const SECCOMP_DATA_NR: u32 = 0;
pub const SECCOMP_DATA_ARCH: u32 = SECCOMP_DATA_NR + size_of::<libc::c_int>() as u32;

#[repr(C)]
#[derive(Debug)]
pub struct seccomp_data {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct seccomp_notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: seccomp_data,
}

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

#[repr(C)]
#[derive(Debug)]
pub struct seccomp_notif_resp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct seccomp_notif_sizes {
    pub seccomp_notif: u16,
    pub seccomp_notif_resp: u16,
    pub seccomp_data: u16,
}

pub unsafe fn seccomp(
    op: libc::c_ulong,
    flags: libc::c_ulong,
    arg: *mut libc::c_void,
) -> libc::c_long {
    libc::syscall(libc::SYS_seccomp, op, flags, arg)
}

const SECCOMP_IOC_MAGIC: u8 = b'!';
ioctl_readwrite!(seccomp_notif_recv, SECCOMP_IOC_MAGIC, 0, seccomp_notif);
ioctl_readwrite!(seccomp_notif_send, SECCOMP_IOC_MAGIC, 1, seccomp_notif_resp);
ioctl_read!(seccomp_notif_id_valid, SECCOMP_IOC_MAGIC, 2, u64);

#[cfg(test)]
mod tests {
    use crate::sys::{
        seccomp, seccomp_data, seccomp_notif, seccomp_notif_resp, seccomp_notif_sizes,
        SECCOMP_GET_NOTIF_SIZES,
    };
    use nix::errno::Errno;
    use std::mem::{size_of, MaybeUninit};

    fn get_notif_sizes() -> nix::Result<seccomp_notif_sizes> {
        let mut sizes = MaybeUninit::zeroed();
        let res = unsafe { seccomp(SECCOMP_GET_NOTIF_SIZES, 0, sizes.as_mut_ptr() as *mut _) };
        Errno::result(res)?;
        Ok(unsafe { sizes.assume_init() })
    }

    #[test]
    fn test_notif_sizes() {
        let sizes = get_notif_sizes().unwrap();
        assert_eq!(sizes.seccomp_data, size_of::<seccomp_data>() as _);
        assert_eq!(sizes.seccomp_notif, size_of::<seccomp_notif>() as _);
        assert_eq!(
            sizes.seccomp_notif_resp,
            size_of::<seccomp_notif_resp>() as _
        );
    }
}
