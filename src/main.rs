//! mac-gate: a DNS resolver that routes the addresses of listed domains
//! into a tunnel before answering, and the daemon that keeps the tunnel.

mod command;
mod config;
mod daemon;
mod degraded;
mod geo;
mod install;
mod link;
mod lists;
mod net;
mod pf;
mod probe;
mod resolver;
mod route;
mod sources;
mod state;
mod sysdns;
mod tunnel;
mod upstream;

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::signal::unix::{SignalKind, signal};

use crate::config::{Rule, When};
use crate::lists::Lists;
use crate::resolver::{Health, Iface, Journal, LinkState, Resolver};
use crate::route::RouteSocket;
use crate::upstream::Upstream;

const USAGE: &str = "usage:
  mac-gate install --config FILE --awg-go FILE --awg FILE
  mac-gate uninstall | on | off
  mac-gate killswitch on|off [--state FILE]
  mac-gate country CODE|auto [--state FILE]
  mac-gate update [--state FILE]
  mac-gate run --config FILE --state FILE [--journal FILE]
      [--listen ADDR:PORT] [--tunnel-dns ADDR] [--libexec DIR] [--window-min N]
      [--use-fakeip auto|off] [--system-dns]
  mac-gate resolve --lists DIR --tunnel IF --network-dns ADDR
      [--tunnel-dns ADDR] [--listen ADDR:PORT] [--use-fakeip] [--journal FILE]";
const LIMIT: Duration = Duration::from_secs(4);
const TUNNEL_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// The resolver alone, on a tunnel someone else keeps up.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    lists: PathBuf,
    tunnel: String,
    network_dns: Ipv4Addr,
    tunnel_dns: Ipv4Addr,
    listen: SocketAddr,
    use_fakeip: bool,
    journal: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Resolve(Args),
    Run(daemon::Config),
    /// The owner's reason for the kill switch, set or taken away.
    Killswitch {
        on: bool,
        state: PathBuf,
    },
    /// The owner's country, or none to ask the services.
    Country {
        code: Option<String>,
        state: PathBuf,
    },
    /// Every source fetched now.
    Update {
        state: PathBuf,
    },
    Install(install::Sources),
    Uninstall,
    On,
    Off,
}

fn bad(flag: &str, value: &str) -> String {
    format!("{flag}: bad value {value}")
}

fn required<T>(v: Option<T>, flag: &str) -> Result<T, String> {
    v.ok_or_else(|| format!("{flag} is required\n{USAGE}"))
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Cmd, String> {
    match it.next().as_deref() {
        Some("resolve") => parse_resolve(it).map(Cmd::Resolve),
        Some("run") => parse_run(it).map(Cmd::Run),
        Some("killswitch") => parse_killswitch(it),
        Some("country") => parse_country(it),
        Some("update") => state_arg(it).map(|state| Cmd::Update { state }),
        Some("install") => parse_install(it).map(Cmd::Install),
        Some("uninstall") => bare(it, Cmd::Uninstall),
        Some("on") => bare(it, Cmd::On),
        Some("off") => bare(it, Cmd::Off),
        _ => Err(USAGE.to_owned()),
    }
}

/// A command that takes no arguments.
fn bare(mut it: impl Iterator<Item = String>, cmd: Cmd) -> Result<Cmd, String> {
    match it.next() {
        None => Ok(cmd),
        Some(_) => Err(USAGE.to_owned()),
    }
}

/// An optional `--state FILE`, which defaults to that of the installed
/// service, and nothing after it.
fn state_arg(mut it: impl Iterator<Item = String>) -> Result<PathBuf, String> {
    match (it.next().as_deref(), it.next(), it.next()) {
        (None, None, None) => Ok(PathBuf::from(install::STATE)),
        (Some("--state"), Some(state), None) => Ok(PathBuf::from(state)),
        _ => Err(USAGE.to_owned()),
    }
}

fn parse_killswitch(mut it: impl Iterator<Item = String>) -> Result<Cmd, String> {
    let on = match it.next().as_deref() {
        Some("on") => true,
        Some("off") => false,
        _ => return Err(USAGE.to_owned()),
    };
    let state = state_arg(it)?;
    Ok(Cmd::Killswitch { on, state })
}

fn parse_country(mut it: impl Iterator<Item = String>) -> Result<Cmd, String> {
    let code = match it.next() {
        Some(c) if c == "auto" => None,
        Some(c) => {
            let upper = c.to_ascii_uppercase();
            if daemon::country_code(&upper).is_none() {
                return Err(format!(
                    "country: {c} is not a code of two letters\n{USAGE}"
                ));
            }
            Some(upper)
        }
        None => return Err(USAGE.to_owned()),
    };
    let state = state_arg(it)?;
    Ok(Cmd::Country { code, state })
}

fn parse_install(mut it: impl Iterator<Item = String>) -> Result<install::Sources, String> {
    let (mut config, mut awg_go, mut awg) = (None, None, None);
    while let Some(flag) = it.next() {
        if flag == "--conf" {
            return Err(
                "--conf: the tunnels are in the settings now, [[tunnel]] with conf = FILE"
                    .to_owned(),
            );
        }
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        let slot = match flag.as_str() {
            "--config" => &mut config,
            "--awg-go" => &mut awg_go,
            "--awg" => &mut awg,
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        };
        *slot = Some(PathBuf::from(value));
    }
    Ok(install::Sources {
        config: required(config, "--config")?,
        awg_go: required(awg_go, "--awg-go")?,
        awg: required(awg, "--awg")?,
    })
}

fn parse_resolve(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut lists = None;
    let mut tunnel = None;
    let mut network_dns = None;
    let mut tunnel_dns = TUNNEL_DNS;
    // Not 5353: that is mDNS, held by mDNSResponder.
    let mut listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 5300));
    let mut use_fakeip = false;
    let mut journal = None;
    while let Some(flag) = it.next() {
        if flag == "--use-fakeip" {
            use_fakeip = true;
            continue;
        }
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--lists" => lists = Some(PathBuf::from(&value)),
            "--tunnel" => tunnel = Some(value.clone()),
            "--network-dns" => network_dns = Some(value.parse().map_err(|_| bad(&flag, &value))?),
            "--tunnel-dns" => tunnel_dns = value.parse().map_err(|_| bad(&flag, &value))?,
            "--listen" => listen = value.parse().map_err(|_| bad(&flag, &value))?,
            "--journal" => journal = Some(PathBuf::from(&value)),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    Ok(Args {
        lists: required(lists, "--lists")?,
        tunnel: required(tunnel, "--tunnel")?,
        network_dns: required(network_dns, "--network-dns")?,
        tunnel_dns,
        listen,
        use_fakeip,
        journal,
    })
}

fn parse_run(mut it: impl Iterator<Item = String>) -> Result<daemon::Config, String> {
    let mut config = None;
    let mut state = None;
    let mut journal = None;
    let mut listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    let mut tunnel_dns = TUNNEL_DNS;
    let mut libexec = PathBuf::from(install::LIBEXEC);
    let mut window = 24 * 3600;
    let mut use_fakeip = true;
    let mut system_dns = false;
    while let Some(flag) = it.next() {
        if flag == "--system-dns" {
            system_dns = true;
            continue;
        }
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--config" => config = Some(PathBuf::from(&value)),
            "--state" => state = Some(PathBuf::from(&value)),
            "--journal" => journal = Some(PathBuf::from(&value)),
            "--listen" => listen = value.parse().map_err(|_| bad(&flag, &value))?,
            "--tunnel-dns" => tunnel_dns = value.parse().map_err(|_| bad(&flag, &value))?,
            "--libexec" => libexec = PathBuf::from(&value),
            "--window-min" => {
                let min: u64 = value.parse().map_err(|_| bad(&flag, &value))?;
                window = min.saturating_mul(60);
            }
            "--use-fakeip" => {
                use_fakeip = match value.as_str() {
                    "auto" => true,
                    "off" => false,
                    _ => return Err(bad(&flag, &value)),
                };
            }
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    Ok(daemon::Config {
        settings: required(config, "--config")?,
        state: required(state, "--state")?,
        journal,
        listen,
        tunnel_dns,
        libexec,
        window,
        use_fakeip,
        system_dns,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cmd = match parse_args(std::env::args().skip(1)) {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let done = match cmd {
        Cmd::Resolve(args) => resolve(args).await,
        Cmd::Run(cfg) => daemon::run(cfg).await,
        Cmd::Killswitch { on, state } => daemon::owner_killswitch(&state, on).map_err(Into::into),
        Cmd::Country { code, state } => {
            daemon::owner_country(&state, code.as_deref()).map_err(Into::into)
        }
        Cmd::Update { state } => daemon::request_update(&state).map_err(Into::into),
        Cmd::Install(src) => install::install(&src).await,
        Cmd::Uninstall => install::uninstall().await,
        Cmd::On => install::on().await,
        Cmd::Off => install::off().await,
    };
    match done {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mac-gate: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn resolve(args: Args) -> Result<(), Box<dyn Error>> {
    let lists = Lists::load_dir(&args.lists)?;
    let tunnel_if = route::if_index(&args.tunnel)?;
    let journal = Journal::open(args.journal.as_deref())?;
    journal.log(format_args!(
        "start suffixes={} subnets={} rejected={} tunnel={}#{} network={} tunnel_dns={} use_fakeip={} listen={}",
        lists.suffix_count(),
        lists.subnets().count(),
        lists.rejected.len(),
        args.tunnel,
        tunnel_if,
        args.network_dns,
        args.tunnel_dns,
        args.use_fakeip,
        args.listen,
    ));
    for line in &lists.rejected {
        journal.log(format_args!("rejected {line}"));
    }
    // One rule, always, with every list, into the one tunnel.
    let rule = Rule {
        name: "resolve".to_owned(),
        when: When::Always,
        lists: lists.names().to_vec(),
        tunnels: vec![0],
    };
    let resolver = Arc::new(Resolver::new(
        lists,
        &[rule],
        vec![args.tunnel.clone()],
        args.tunnel_dns,
        RouteSocket::open()?,
        journal,
        None,
    ));
    resolver.set_upstream(Some(Upstream {
        server: SocketAddrV4::new(args.network_dns, 53),
        bound_if: None,
    }));
    resolver.set_use_fakeip(args.use_fakeip);
    resolver.set_country("RU");
    resolver.set_link(
        0,
        LinkState {
            iface: Some(Iface {
                name: args.tunnel.clone(),
                index: tunnel_if,
            }),
            generation: 1,
            health: Health::Up,
            since: Some(std::time::Instant::now()),
            ..LinkState::default()
        },
    );
    // Everything that can fail goes before the first route: an early exit
    // must not leave routes behind.
    let udp = UdpSocket::bind(args.listen).await?;
    let tcp = TcpListener::bind(args.listen).await?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    resolver.reconcile();
    resolver.journal.log(format_args!("ready"));
    tokio::spawn(serve(Arc::clone(&resolver), udp, tcp));
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    let removed = resolver.remove_all();
    resolver
        .journal
        .log(format_args!("stop routes_removed={removed}"));
    Ok(())
}

/// Answers DNS over UDP and TCP, each query in a task of its own.
async fn serve(resolver: Arc<Resolver>, udp: UdpSocket, tcp: TcpListener) {
    let udp = Arc::new(udp);
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            got = udp.recv_from(&mut buf) => {
                let Ok((n, peer)) = got else { continue };
                let query = buf.get(..n).unwrap_or_default().to_vec();
                let (resolver, udp) = (Arc::clone(&resolver), Arc::clone(&udp));
                tokio::spawn(async move {
                    if let Some(answer) = resolver.handle(&query).await {
                        let _ = udp.send_to(&answer, peer).await;
                    }
                });
            }
            got = tcp.accept() => {
                if let Ok((stream, _)) = got {
                    tokio::spawn(serve_tcp(Arc::clone(&resolver), stream));
                }
            }
        }
    }
}

/// DNS over TCP: two-byte length, then the message, as many as the client sends.
async fn serve_tcp(resolver: Arc<Resolver>, mut stream: TcpStream) {
    while let Ok(len) = stream.read_u16().await {
        let mut query = vec![0u8; usize::from(len)];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        let Some(answer) = resolver.handle(&query).await else {
            return;
        };
        let Ok(n) = u16::try_from(answer.len()) else {
            return;
        };
        let mut framed = n.to_be_bytes().to_vec();
        framed.extend_from_slice(&answer);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(s: &str) -> Result<Cmd, String> {
        parse_args(s.split_whitespace().map(str::to_owned))
    }

    fn resolve_args(s: &str) -> Args {
        match cmd(s).unwrap() {
            Cmd::Resolve(a) => a,
            _ => panic!("not resolve"),
        }
    }

    #[test]
    fn parses_resolve_required_and_defaults() {
        let a = resolve_args("resolve --lists /l --tunnel utun4 --network-dns 192.168.1.1");
        assert_eq!(a.lists, PathBuf::from("/l"));
        assert_eq!(a.tunnel, "utun4");
        assert_eq!(a.network_dns, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(a.tunnel_dns, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(a.listen, "127.0.0.1:5300".parse().unwrap());
        assert!(!a.use_fakeip);
        assert!(a.journal.is_none());
    }

    #[test]
    fn parses_resolve_options() {
        let a = resolve_args(
            "resolve --use-fakeip --lists /l --tunnel utun9 --network-dns 10.0.0.1 \
             --tunnel-dns 9.9.9.9 --listen 127.0.0.1:53 --journal /j",
        );
        assert!(a.use_fakeip);
        assert_eq!(a.tunnel_dns, Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(a.listen.port(), 53);
        assert_eq!(a.journal, Some(PathBuf::from("/j")));
    }

    #[test]
    fn parses_run() {
        let Cmd::Run(c) = cmd("run --config /l --state /s --window-min 3").unwrap() else {
            panic!("not run");
        };
        assert_eq!(c.settings, PathBuf::from("/l"));
        assert_eq!(c.state, PathBuf::from("/s"));
        assert_eq!(c.listen, "127.0.0.1:53".parse().unwrap());
        assert_eq!(c.libexec, PathBuf::from("/usr/local/libexec/mac-gate"));
        assert_eq!(c.window, 180);
        assert!(c.use_fakeip);
        let Cmd::Run(c) = cmd("run --config /l --state /s --use-fakeip off").unwrap() else {
            panic!("not run");
        };
        assert_eq!(c.window, 24 * 3600);
        assert!(!c.use_fakeip);
    }

    #[test]
    fn parses_killswitch() {
        assert_eq!(
            cmd("killswitch on --state /s/routes").unwrap(),
            Cmd::Killswitch {
                on: true,
                state: PathBuf::from("/s/routes")
            }
        );
        assert!(matches!(
            cmd("killswitch off --state /s/routes"),
            Ok(Cmd::Killswitch { on: false, .. })
        ));
        assert!(cmd("killswitch --state /s").is_err());
        assert_eq!(
            cmd("killswitch on").unwrap(),
            Cmd::Killswitch {
                on: true,
                state: PathBuf::from("/var/db/mac-gate/routes")
            }
        );
        assert!(cmd("killswitch on --state").is_err());
        assert!(cmd("killswitch on --state /s extra").is_err());
    }

    #[test]
    fn parses_country() {
        assert_eq!(
            cmd("country de").unwrap(),
            Cmd::Country {
                code: Some("DE".to_owned()),
                state: PathBuf::from("/var/db/mac-gate/routes")
            }
        );
        assert_eq!(
            cmd("country auto --state /s/routes").unwrap(),
            Cmd::Country {
                code: None,
                state: PathBuf::from("/s/routes")
            }
        );
        assert!(cmd("country").is_err());
        assert!(cmd("country RUS").is_err());
        assert!(cmd("country R1").is_err());
    }

    #[test]
    fn parses_update() {
        assert_eq!(
            cmd("update").unwrap(),
            Cmd::Update {
                state: PathBuf::from("/var/db/mac-gate/routes")
            }
        );
        assert_eq!(
            cmd("update --state /s/routes").unwrap(),
            Cmd::Update {
                state: PathBuf::from("/s/routes")
            }
        );
        assert!(cmd("update now").is_err());
    }

    #[test]
    fn parses_install_and_bare_commands() {
        assert_eq!(
            cmd("install --awg /b/awg --awg-go /b/go --config /l").unwrap(),
            Cmd::Install(install::Sources {
                config: PathBuf::from("/l"),
                awg_go: PathBuf::from("/b/go"),
                awg: PathBuf::from("/b/awg"),
            })
        );
        assert_eq!(cmd("uninstall").unwrap(), Cmd::Uninstall);
        assert_eq!(cmd("on").unwrap(), Cmd::On);
        assert_eq!(cmd("off").unwrap(), Cmd::Off);
    }

    #[test]
    fn parses_system_dns() {
        let Cmd::Run(c) = cmd("run --system-dns --config /l --state /s").unwrap() else {
            panic!("not run");
        };
        assert!(c.system_dns);
        let Cmd::Run(c) = cmd("run --config /l --state /s").unwrap() else {
            panic!("not run");
        };
        assert!(!c.system_dns);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(cmd("").is_err());
        assert!(cmd("serve").is_err());
        assert!(cmd("resolve --lists /l --tunnel utun4").is_err());
        assert!(cmd("resolve --lists /l --tunnel utun4 --network-dns x").is_err());
        assert!(cmd("resolve --lists").is_err());
        assert!(cmd("resolve --bogus 1").is_err());
        assert!(cmd("run --config /l").is_err());
        assert!(cmd("run --config /l --state /s --window-min x").is_err());
        assert!(cmd("run --lists /l --state /s").is_err());
        assert!(cmd("run --conf /c --config /l --state /s").is_err());
        assert!(cmd("run --use-fakeip").is_err());
        assert!(cmd("run --config /l --state /s --use-fakeip yes").is_err());
        assert!(cmd("off now").is_err());
        assert!(cmd("install --config /l --awg-go /g").is_err());
        assert!(cmd("install --lists /l --awg-go /g --awg /a").is_err());
        assert!(
            cmd("install --conf /c --config /l --awg-go /g --awg /a")
                .unwrap_err()
                .contains("[[tunnel]]")
        );
        assert!(cmd("install --config /l --bogus 1").is_err());
    }
}
