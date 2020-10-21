use nix::cmsg_space;
use nix::libc;
use nix::sys::socket;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
};
use nix::sys::stat::Mode;
use nix::sys::uio::IoVec;
use nix::unistd::{close, fork, mkdir, ForkResult, Pid};
use seccomp_notif::{Filter, FilterAction, NotifyFd};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::exit;
use std::slice;

fn send_fd<F: AsRawFd>(sock: RawFd, fd: &F) -> nix::Result<()> {
    let fd = fd.as_raw_fd();
    let cmsgs = [ControlMessage::ScmRights(slice::from_ref(&fd))];

    let iov = [IoVec::from_slice(b"x")];

    socket::sendmsg(sock, &iov, &cmsgs, MsgFlags::empty(), None)?;
    Ok(())
}

fn recv_fd<F: FromRawFd>(sock: RawFd) -> nix::Result<Option<F>> {
    let mut iov_buf = [];
    let iov = [IoVec::from_mut_slice(&mut iov_buf)];

    let mut cmsg_buf = cmsg_space!(RawFd);
    let msg = socket::recvmsg(sock, &iov, Some(&mut cmsg_buf), MsgFlags::empty())?;
    match msg.cmsgs().next() {
        Some(ControlMessageOwned::ScmRights(fds)) if fds.len() > 0 => {
            let fd = unsafe { F::from_raw_fd(fds[0]) };
            Ok(Some(fd))
        }
        _ => Ok(None),
    }
}

fn spawn_target_process(sock: RawFd) -> nix::Result<Pid> {
    match unsafe { fork() }? {
        ForkResult::Parent { child } => return Ok(child),
        ForkResult::Child => {}
    }

    println!("running target");
    let notify_fd = Filter::new(FilterAction::Allow)
        .match_nr(libc::SYS_mkdir as _, FilterAction::Notify)
        .install()?;
    println!("installed filter");
    send_fd(sock, &notify_fd)?;
    close(sock)?;

    println!("calling mkdir");
    let res = mkdir("test", Mode::S_IRUSR | Mode::S_IWUSR);
    print!("mkdir finished: {:?}", res);

    exit(0)
}

fn handle_notifications(notify_fd: NotifyFd) -> nix::Result<()> {
    loop {
        println!("waiting on next notification");
        let req = notify_fd.recv()?;
        println!("got notification: {:?}", req);

        let data = &req.as_raw().data;
        assert_eq!(data.nr, libc::SYS_mkdir as _);
        //assert_eq!(req.data.arch, AUDIT_ARCH_X86_64);

        let mut path = read_process_memory(req.as_raw().pid, data.args[0]);
        let path_len = path.iter().position(|c| *c == b'\x00').unwrap();
        path.truncate(path_len);
        let path = String::from_utf8(path)?;
        println!("path: {}", path);

        req.check()?;
        req.reply_error(libc::EPERM)?;
    }
}

fn read_process_memory(pid: u32, offset: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let mem = File::open(format!("/proc/{}/mem", pid)).unwrap();
    let nread = mem.read_at(&mut buf, offset).unwrap();
    buf.truncate(nread);
    buf
}

fn main() {
    let (s1, s2) = socket::socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap();

    let _target_pid = spawn_target_process(s1).unwrap();
    let notify_fd = recv_fd(s2).unwrap().unwrap();
    close(s1).unwrap();
    close(s2).unwrap();

    handle_notifications(notify_fd).unwrap();
}
