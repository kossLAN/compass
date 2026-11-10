use std::io;
use std::os::fd::BorrowedFd;

use socket2::SockRef;

pub trait Protect: Send + Sync {
    fn protect(&self, socket: BorrowedFd<'_>) -> io::Result<()>;
}

pub struct Fwmark(pub u32);

impl Protect for Fwmark {
    fn protect(&self, socket: BorrowedFd<'_>) -> io::Result<()> {
        SockRef::from(&socket).set_mark(self.0)
    }
}
