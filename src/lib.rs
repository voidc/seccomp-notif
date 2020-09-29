//! Links:
//!
//!
use nix::errno::Errno;
use nix::libc;
use nix::unistd::close;
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use sys::*;

mod sys;

pub use sys::seccomp_notif as Notif;
pub use sys::seccomp_notif_resp as NotifResp;

#[repr(u32)]
pub enum FilterAction {
    Allow = SECCOMP_RET_ALLOW,
    Notify = SECCOMP_RET_USER_NOTIF,
    Kill = SECCOMP_RET_KILL_PROCESS,
}

pub struct Filter {
    rules: Vec<sock_filter>,
    default_action: FilterAction,
}

impl Filter {
    pub fn new(default_action: FilterAction) -> Self {
        let preamble = vec![
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR),
            BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        ];

        Filter {
            rules: preamble,
            default_action,
        }
    }

    pub fn match_nr(mut self, syscall_nr: u32, action: FilterAction) -> Self {
        self.rules
            .push(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
        self.rules.push(BPF_STMT(BPF_RET | BPF_K, action as _));
        self
    }

    pub fn install(mut self) -> nix::Result<NotifyFd> {
        self.rules
            .push(BPF_STMT(BPF_RET | BPF_K, self.default_action as _));

        let mut prog = sock_fprog {
            len: self.rules.len() as _,
            filter: self.rules.as_ptr() as _,
        };

        set_no_new_privs()?;
        let notify_fd = unsafe {
            seccomp(
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &mut prog as *mut _ as *mut libc::c_void,
            )
        };

        Errno::result(notify_fd)?;
        Ok(unsafe { NotifyFd::from_raw_fd(notify_fd as _) })
    }
}

fn set_no_new_privs() -> nix::Result<()> {
    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    Errno::result(res)?;
    Ok(())
}

pub struct NotifyFd {
    fd: RawFd,
}

impl NotifyFd {
    pub fn recv(&self) -> nix::Result<Notif> {
        let mut res = MaybeUninit::zeroed();
        unsafe {
            seccomp_notif_recv(self.fd, res.as_mut_ptr())?;
            Ok(res.assume_init())
        }
    }

    pub fn send(&self, res: NotifResp) -> nix::Result<()> {
        let mut res = res;
        unsafe {
            seccomp_notif_send(self.fd, &mut res as *mut _)?;
        }
        Ok(())
    }

    pub fn check_id(&self, id: u64) -> nix::Result<()> {
        let mut id = id;
        unsafe {
            seccomp_notif_id_valid(self.fd, &mut id as *mut _)?;
        }
        Ok(())
    }
}

impl Drop for NotifyFd {
    fn drop(&mut self) {
        println!("drop NotifyFd");
        close(self.fd).unwrap()
    }
}

impl FromRawFd for NotifyFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NotifyFd { fd }
    }
}

impl IntoRawFd for NotifyFd {
    fn into_raw_fd(self) -> RawFd {
        let NotifyFd { fd } = self;
        fd
    }
}

impl AsRawFd for NotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
