//! One DNS exchange with an upstream server: UDP, then TCP when the answer is
//! truncated. A server may be bound to an interface (`IP_BOUND_IF`): that is how
//! queries go through the tunnel, which has only a scoped default route.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU32;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::time::timeout;

#[derive(Clone, Copy, Debug)]
pub struct Upstream {
    pub server: SocketAddrV4,
    pub bound_if: Option<NonZeroU32>,
}

impl Upstream {
    /// Sends the query bytes as they are and returns the answer bytes.
    pub async fn exchange(&self, query: &[u8], limit: Duration) -> io::Result<Vec<u8>> {
        let answer = timeout(limit, self.udp(query))
            .await
            .map_err(|_| timed_out(self.server))??;
        if !truncated(&answer) {
            return Ok(answer);
        }
        timeout(limit, self.tcp(query))
            .await
            .map_err(|_| timed_out(self.server))?
    }

    fn socket(&self, ty: Type, proto: Protocol) -> io::Result<Socket> {
        let s = Socket::new(Domain::IPV4, ty, Some(proto))?;
        if let Some(index) = self.bound_if {
            s.bind_device_by_index_v4(Some(index))?;
        }
        s.set_nonblocking(true)?;
        Ok(s)
    }

    async fn udp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let s = self.socket(Type::DGRAM, Protocol::UDP)?;
        s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
        let sock = UdpSocket::from_std(s.into())?;
        sock.connect(SocketAddr::V4(self.server)).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; 65535];
        loop {
            let n = sock.recv(&mut buf).await?;
            // A fresh socket per query, connected to the server: only the id
            // is left to check.
            if n >= 12 && buf.get(..2) == query.get(..2) {
                buf.truncate(n);
                return Ok(buf);
            }
        }
    }

    async fn tcp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let s = self.socket(Type::STREAM, Protocol::TCP)?;
        let mut stream = TcpSocket::from_std_stream(s.into())
            .connect(SocketAddr::V4(self.server))
            .await?;
        let len = u16::try_from(query.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too long"))?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await?;
        let n = usize::from(stream.read_u16().await?);
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

fn truncated(msg: &[u8]) -> bool {
    msg.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

fn timed_out(server: SocketAddrV4) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("no answer from {server}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_bit() {
        assert!(truncated(&[0, 1, 0x83, 0x80]));
        assert!(!truncated(&[0, 1, 0x81, 0x80]));
        assert!(!truncated(&[0, 1]));
    }
}
