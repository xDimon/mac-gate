//! Routes through an interface over the routing socket: the messages
//! `route -n add -interface <if>` sends, without spawning `route`.

use std::ffi::CString;
use std::io::{self, Write};
use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, Shutdown};
use std::sync::atomic::{AtomicI32, Ordering};

use socket2::{Domain, Socket, Type};

use crate::lists::Subnet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Added,
    Existed,
    /// Existed and now points at the interface.
    Moved,
}

pub struct RouteSocket {
    sock: Socket,
    seq: AtomicI32,
}

impl RouteSocket {
    pub fn open() -> io::Result<Self> {
        let sock = Socket::new(Domain::from(libc::PF_ROUTE), Type::RAW, None)?;
        // Nothing is read back: a failed write already carries the errno, and
        // unread echoes of every route change would only fill the buffer.
        sock.shutdown(Shutdown::Read)?;
        Ok(Self {
            sock,
            seq: AtomicI32::new(0),
        })
    }

    /// Adds a route to `dst` through the interface `ifindex`; an existing
    /// route to the same destination is left as it is.
    pub fn add(&self, dst: Subnet, ifindex: u16) -> io::Result<Outcome> {
        match self.send(&message(libc::RTM_ADD, dst, Some(ifindex), self.next_seq())) {
            Ok(()) => Ok(Outcome::Added),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(Outcome::Existed),
            Err(e) => Err(e),
        }
    }

    /// Adds the route, or puts a new one in place of an existing one. Not a
    /// change in place: an open connection keeps the route it had, deleted
    /// or not, and a new route does not take it over.
    /// So connections started through the old interface live
    /// out there, and new ones go through the new. Between the two a new
    /// connection finds no route, and pf holds it until a retransmit.
    pub fn set(&self, dst: Subnet, ifindex: u16) -> io::Result<Outcome> {
        if self.add(dst, ifindex)? == Outcome::Added {
            return Ok(Outcome::Added);
        }
        self.delete(dst)?;
        self.add(dst, ifindex).map(|_| Outcome::Moved)
    }

    /// Returns false when there was no such route.
    pub fn delete(&self, dst: Subnet) -> io::Result<bool> {
        match self.send(&message(libc::RTM_DELETE, dst, None, self.next_seq())) {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn next_seq(&self) -> i32 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn send(&self, msg: &[u8]) -> io::Result<()> {
        // One write is one message; the kernel takes it whole or fails it.
        let n = (&self.sock).write(msg)?;
        if n == msg.len() {
            Ok(())
        } else {
            Err(io::Error::other("short write to the route socket"))
        }
    }
}

const HDR: usize = size_of::<libc::rt_msghdr>();
const SIN_LEN: u8 = 16;
const SDL_LEN: u8 = 20;

/// A routing message: header, then the addresses in RTA_* bit order, each
/// already a multiple of 4 bytes as the kernel expects.
fn message(kind: i32, dst: Subnet, ifindex: Option<u16>, seq: i32) -> Vec<u8> {
    let host = dst.prefix == 32;
    let mut flags = libc::RTF_UP | libc::RTF_STATIC;
    if host {
        flags |= libc::RTF_HOST;
    }
    let mut addrs = libc::RTA_DST;
    let mut msg = vec![0u8; HDR];
    push_sin(&mut msg, dst.addr);
    if let Some(index) = ifindex {
        addrs |= libc::RTA_GATEWAY;
        push_sdl(&mut msg, index);
    }
    if !host {
        addrs |= libc::RTA_NETMASK;
        push_sin(&mut msg, dst.netmask());
    }
    let len = u16::try_from(msg.len()).unwrap_or(u16::MAX);
    put(
        &mut msg,
        offset_of!(libc::rt_msghdr, rtm_msglen),
        &len.to_ne_bytes(),
    );
    put(
        &mut msg,
        offset_of!(libc::rt_msghdr, rtm_version),
        &[byte(libc::RTM_VERSION)],
    );
    put(
        &mut msg,
        offset_of!(libc::rt_msghdr, rtm_type),
        &[byte(kind)],
    );
    put(
        &mut msg,
        offset_of!(libc::rt_msghdr, rtm_flags),
        &flags.to_ne_bytes(),
    );
    put(
        &mut msg,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        &addrs.to_ne_bytes(),
    );
    put(
        &mut msg,
        offset_of!(libc::rt_msghdr, rtm_seq),
        &seq.to_ne_bytes(),
    );
    msg
}

fn byte(v: i32) -> u8 {
    u8::try_from(v).unwrap_or(0)
}

fn put(msg: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(dst) = msg.get_mut(at..at + bytes.len()) {
        dst.copy_from_slice(bytes);
    }
}

fn push_sin(msg: &mut Vec<u8>, addr: Ipv4Addr) {
    msg.extend_from_slice(&[SIN_LEN, byte(libc::AF_INET), 0, 0]);
    msg.extend_from_slice(&addr.octets());
    msg.extend_from_slice(&[0; 8]);
}

/// A link-level address that names the interface by index only; the kernel
/// resolves it to the interface, as for `route add -interface`.
fn push_sdl(msg: &mut Vec<u8>, index: u16) {
    msg.extend_from_slice(&[SDL_LEN, byte(libc::AF_LINK)]);
    msg.extend_from_slice(&index.to_ne_bytes());
    msg.extend_from_slice(&[0; 16]);
}

#[allow(unsafe_code)]
pub fn if_index(name: &str) -> io::Result<u16> {
    let c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in interface name"))?;
    // SAFETY: `c` is a valid NUL-terminated string that outlives the call,
    // and if_nametoindex only reads it.
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    u16::try_from(index)
        .ok()
        .filter(|&i| i != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no interface {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<const N: usize>(msg: &[u8], at: usize) -> [u8; N] {
        msg[at..at + N].try_into().unwrap()
    }

    #[test]
    fn sizes_match_the_kernel_structs() {
        assert_eq!(usize::from(SIN_LEN), size_of::<libc::sockaddr_in>());
        assert_eq!(usize::from(SDL_LEN), size_of::<libc::sockaddr_dl>());
    }

    #[test]
    fn host_add_has_destination_and_interface() {
        let msg = message(
            libc::RTM_ADD,
            Subnet::host(Ipv4Addr::new(100, 64, 0, 1)),
            Some(23),
            7,
        );
        assert_eq!(msg.len(), HDR + 16 + 20);
        let len = u16::from_ne_bytes(field(&msg, offset_of!(libc::rt_msghdr, rtm_msglen)));
        assert_eq!(usize::from(len), msg.len());
        assert_eq!(msg[offset_of!(libc::rt_msghdr, rtm_version)], 5);
        assert_eq!(msg[offset_of!(libc::rt_msghdr, rtm_type)], 1);
        let flags = i32::from_ne_bytes(field(&msg, offset_of!(libc::rt_msghdr, rtm_flags)));
        assert_eq!(flags, libc::RTF_UP | libc::RTF_STATIC | libc::RTF_HOST);
        let addrs = i32::from_ne_bytes(field(&msg, offset_of!(libc::rt_msghdr, rtm_addrs)));
        assert_eq!(addrs, libc::RTA_DST | libc::RTA_GATEWAY);
        assert_eq!(
            i32::from_ne_bytes(field(&msg, offset_of!(libc::rt_msghdr, rtm_seq))),
            7
        );
        assert_eq!(&msg[HDR..HDR + 8], &[16, 2, 0, 0, 100, 64, 0, 1]);
        assert_eq!(msg[HDR + 16], 20);
        assert_eq!(msg[HDR + 17], 18);
        assert_eq!(u16::from_ne_bytes(field(&msg, HDR + 18)), 23);
    }

    #[test]
    fn subnet_delete_has_destination_and_mask() {
        let net = Subnet {
            addr: Ipv4Addr::new(149, 154, 160, 0),
            prefix: 20,
        };
        let msg = message(libc::RTM_DELETE, net, None, 1);
        assert_eq!(msg.len(), HDR + 16 + 16);
        let addrs = i32::from_ne_bytes(field(&msg, offset_of!(libc::rt_msghdr, rtm_addrs)));
        assert_eq!(addrs, libc::RTA_DST | libc::RTA_NETMASK);
        let flags = i32::from_ne_bytes(field(&msg, offset_of!(libc::rt_msghdr, rtm_flags)));
        assert_eq!(flags & libc::RTF_HOST, 0);
        assert_eq!(&msg[HDR + 4..HDR + 8], &[149, 154, 160, 0]);
        assert_eq!(&msg[HDR + 16 + 4..HDR + 16 + 8], &[255, 255, 240, 0]);
    }
}
