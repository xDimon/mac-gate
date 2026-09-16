//! The country of the direct address: asked of several services at once,
//! past the tunnels, bound to the physical interface. The code most of the
//! answers agree on is the country; with no majority, there is none.
//!
//! A service the router takes into its own tunnel (a fake address), or
//! whose address the lists hold, is passed over: its answer would be the
//! country of an exit, or pf would hold it back.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::command;
use crate::net::{self, Network};
use crate::resolver::{has_fakeip, ipv4_answers};

const LIMIT: Duration = Duration::from_secs(5);
/// Services that answer with the country of the address that asks.
const SERVICES: [&str; 3] = [
    "https://1.1.1.1/cdn-cgi/trace",
    "https://ipinfo.io/country",
    "https://ifconfig.co/country-iso",
];

/// The country, if the answers agree, and what each service said.
pub struct Asked {
    pub country: Option<String>,
    pub shown: String,
}

/// Asks every service at once; `held` tells an address pf may hold back.
pub async fn country(net: &Network, held: impl Fn(Ipv4Addr) -> bool) -> Asked {
    let [a, b, c] = SERVICES;
    let (ra, rb, rc) = tokio::join!(ask(a, net, &held), ask(b, net, &held), ask(c, net, &held));
    let answers = [ra, rb, rc];
    let shown = SERVICES
        .iter()
        .zip(&answers)
        .map(|(url, r)| {
            let host = host_of(url).unwrap_or(url);
            match r {
                Ok(code) => format!("{host}={code}"),
                Err(e) => format!("{host}=({e})"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    Asked {
        country: majority(&answers),
        shown,
    }
}

fn host_of(url: &str) -> Option<&str> {
    url.strip_prefix("https://")?.split('/').next()
}

async fn ask(url: &str, net: &Network, held: &impl Fn(Ipv4Addr) -> bool) -> Result<String, String> {
    let host = host_of(url).ok_or("not an https URL")?;
    let literal = host.parse::<Ipv4Addr>().ok();
    let ip = if let Some(ip) = literal {
        ip
    } else {
        let answer = net::query_a(net.upstream(), &format!("{host}."), LIMIT)
            .await
            .map_err(|e| e.to_string())?;
        if has_fakeip(&answer) {
            return Err("fakeip".to_owned());
        }
        *ipv4_answers(&answer).first().ok_or("no address")?
    };
    if held(ip) {
        return Err(format!("{ip} listed"));
    }
    let secs = LIMIT.as_secs().to_string();
    let resolve = format!("{host}:443:{ip}");
    let mut args = vec!["-s", "-f", "-m", &secs, "--interface", &net.iface];
    if literal.is_none() {
        args.extend(["--resolve", &resolve]);
    }
    args.push(url);
    let body = command::run("/usr/bin/curl", &args, None, LIMIT + Duration::from_secs(2))
        .await
        .map_err(|e| e.to_string())?;
    code(&body).ok_or_else(|| "no country in the answer".to_owned())
}

/// Two capital letters on a line of their own, or after `loc=` as in the
/// trace of Cloudflare.
fn code(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let v = line.trim();
        let v = v.strip_prefix("loc=").unwrap_or(v);
        (v.len() == 2 && v.bytes().all(|b| b.is_ascii_uppercase())).then(|| v.to_owned())
    })
}

/// The code more than half of the answers give.
fn majority(answers: &[Result<String, String>]) -> Option<String> {
    let codes: Vec<&str> = answers.iter().filter_map(|a| a.as_deref().ok()).collect();
    codes
        .iter()
        .find(|c| codes.iter().filter(|d| d == c).count() * 2 > codes.len())
        .map(|c| (*c).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_in_answers() {
        let trace =
            "fl=123\nh=1.1.1.1\nip=203.0.113.7\ncolo=XYZ\nhttp=http/2\nloc=DE\ntls=TLSv1.3\n";
        assert_eq!(code(trace).as_deref(), Some("DE"));
        assert_eq!(code("FR\n").as_deref(), Some("FR"));
        assert_eq!(code("  NL  ").as_deref(), Some("NL"));
        assert_eq!(code("<html>not found</html>"), None);
        assert_eq!(code("de\n"), None);
        assert_eq!(code(""), None);
    }

    #[test]
    fn most_answers_agree() {
        let ok = |c: &str| Ok(c.to_owned());
        let fail = || Err("x".to_owned());
        assert_eq!(
            majority(&[ok("DE"), ok("DE"), ok("FR")]).as_deref(),
            Some("DE")
        );
        assert_eq!(
            majority(&[ok("DE"), fail(), ok("DE")]).as_deref(),
            Some("DE")
        );
        assert_eq!(majority(&[ok("DE"), fail(), fail()]).as_deref(), Some("DE"));
        assert_eq!(majority(&[ok("DE"), ok("FR"), fail()]), None);
        assert_eq!(majority(&[ok("DE"), ok("FR"), ok("NL")]), None);
        assert_eq!(majority(&[fail(), fail(), fail()]), None);
        assert_eq!(host_of(SERVICES[1]), Some("ipinfo.io"));
    }
}
