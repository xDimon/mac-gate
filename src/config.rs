//! The settings file: the lists and where each takes its entries from, the
//! tunnels, and the rules that send lists into tunnels.
//!
//! A list is one or more sources, read in order and merged: a file beside
//! the settings, or a URL fetched from time to time. A tunnel is an
//! awg-quick file beside the settings. A rule takes lists into its tunnels,
//! the first while it carries and the rest in reserve, when its condition
//! holds; a name in the lists of two rules goes to the one written first.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::degraded;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    watch: Option<RawWatch>,
    #[serde(rename = "list", default)]
    lists: Vec<RawList>,
    #[serde(rename = "tunnel", default)]
    tunnels: Vec<RawTunnel>,
    #[serde(rename = "rule", default)]
    rules: Vec<RawRule>,
}

/// What the watchdog is told; every key has a default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWatch {
    /// Seconds a degraded tunnel is left alone; 0 - for as long as it
    /// takes.
    degraded_grace: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawList {
    name: String,
    sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunnel {
    name: String,
    conf: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    name: String,
    when: String,
    lists: Vec<String>,
    tunnels: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A path relative to the directory of the settings, never out of it:
    /// the installed settings find their files beside them.
    File(PathBuf),
    Url(String),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(p) => write!(f, "{}", p.display()),
            Self::Url(u) => f.write_str(u),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    pub name: String,
    pub sources: Vec<Source>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tunnel {
    pub name: String,
    /// Beside the settings, as a file source.
    pub conf: PathBuf,
}

/// When a rule is in force, by the country of the direct address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum When {
    Always,
    /// In this country, a code of two capital letters.
    In(String),
    /// Anywhere but in this country.
    Out(String),
}

impl When {
    fn parse(text: &str) -> Option<Self> {
        if text == "always" {
            return Some(Self::Always);
        }
        let (out, code) = match text.strip_prefix('!') {
            Some(c) => (true, c),
            None => (false, text),
        };
        if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
            return None;
        }
        let code = code.to_owned();
        Some(if out { Self::Out(code) } else { Self::In(code) })
    }

    pub fn holds(&self, country: &str) -> bool {
        match self {
            Self::Always => true,
            Self::In(c) => c == country,
            Self::Out(c) => c != country,
        }
    }
}

impl fmt::Display for When {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Always => f.write_str("always"),
            Self::In(c) => f.write_str(c),
            Self::Out(c) => write!(f, "!{c}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub when: When,
    /// Names of lists.
    pub lists: Vec<String>,
    /// Indices into the tunnels of the settings, in the order of priority.
    pub tunnels: Vec<usize>,
}

/// No Default: zero `degraded_grace` means patience without end, which is
/// not what an empty value should stand for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub lists: Vec<List>,
    pub tunnels: Vec<Tunnel>,
    pub rules: Vec<Rule>,
    /// How long a tunnel that the peer still answers through, while no
    /// probe gets past it, is left alone; zero - for as long as it takes.
    pub degraded_grace: Duration,
}

impl Settings {
    pub fn urls(&self) -> impl Iterator<Item = &str> {
        self.sources().filter_map(|s| match s {
            Source::Url(u) => Some(u.as_str()),
            Source::File(_) => None,
        })
    }

    pub fn files(&self) -> impl Iterator<Item = &Path> {
        self.sources().filter_map(|s| match s {
            Source::File(p) => Some(p.as_path()),
            Source::Url(_) => None,
        })
    }

    fn sources(&self) -> impl Iterator<Item = &Source> {
        self.lists.iter().flat_map(|l| &l.sources)
    }
}

pub fn load(path: &Path) -> Result<Settings, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// A name goes into the state file and the journal as one word.
fn name(kind: &str, name: &str, seen: &mut HashSet<String>) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "{kind} name {name:?}: letters, digits, _ and - only"
        ));
    }
    if !seen.insert(name.to_owned()) {
        return Err(format!("{kind} {name}: named twice"));
    }
    Ok(())
}

/// Every name once, and each of the known ones.
fn refs(rule: &str, kind: &str, names: &[String], known: &[&str]) -> Result<(), String> {
    if names.is_empty() {
        return Err(format!("rule {rule}: no {kind}s"));
    }
    let mut seen = HashSet::new();
    for n in names {
        if !known.contains(&n.as_str()) {
            return Err(format!("rule {rule}: no {kind} {n}"));
        }
        if !seen.insert(n) {
            return Err(format!("rule {rule}: {kind} {n} twice"));
        }
    }
    Ok(())
}

pub fn parse(text: &str) -> Result<Settings, String> {
    let raw: RawSettings = toml::from_str(text).map_err(|e| e.to_string())?;
    let degraded_grace = raw
        .watch
        .as_ref()
        .and_then(|w| w.degraded_grace)
        .map_or(degraded::GRACE, Duration::from_secs);
    if raw.lists.is_empty() {
        return Err("no [[list]]".to_owned());
    }
    if raw.tunnels.is_empty() {
        return Err("no [[tunnel]]".to_owned());
    }
    if raw.rules.is_empty() {
        return Err("no [[rule]]".to_owned());
    }
    let mut seen = HashSet::new();
    let mut lists = Vec::new();
    for l in raw.lists {
        name("list", &l.name, &mut seen)?;
        if l.sources.is_empty() {
            return Err(format!("list {}: no sources", l.name));
        }
        let sources = l
            .sources
            .iter()
            .map(|s| source(s).map_err(|e| format!("list {}: {s}: {e}", l.name)))
            .collect::<Result<_, _>>()?;
        lists.push(List {
            name: l.name,
            sources,
        });
    }
    let mut seen = HashSet::new();
    let mut confs = HashSet::new();
    let mut tunnels = Vec::new();
    for t in raw.tunnels {
        name("tunnel", &t.name, &mut seen)?;
        let conf = file(&t.conf).map_err(|e| format!("tunnel {}: {}: {e}", t.name, t.conf))?;
        // One key from two processes: the server keeps one of them.
        if !confs.insert(conf.clone()) {
            return Err(format!("tunnel {}: {} used twice", t.name, t.conf));
        }
        tunnels.push(Tunnel { name: t.name, conf });
    }
    let list_names: Vec<&str> = lists.iter().map(|l| l.name.as_str()).collect();
    let tunnel_names: Vec<&str> = tunnels.iter().map(|t| t.name.as_str()).collect();
    let mut seen = HashSet::new();
    let mut rules = Vec::new();
    for r in raw.rules {
        name("rule", &r.name, &mut seen)?;
        let when = When::parse(&r.when).ok_or_else(|| {
            format!(
                "rule {}: when {:?}: \"always\", a country code such as \"RU\", or \"!RU\"",
                r.name, r.when
            )
        })?;
        refs(&r.name, "list", &r.lists, &list_names)?;
        refs(&r.name, "tunnel", &r.tunnels, &tunnel_names)?;
        let order = r
            .tunnels
            .iter()
            .filter_map(|t| tunnel_names.iter().position(|n| n == t))
            .collect();
        rules.push(Rule {
            name: r.name,
            when,
            lists: r.lists,
            tunnels: order,
        });
    }
    // What no rule takes would be fetched, or kept up, for nothing.
    for l in &list_names {
        if !rules.iter().any(|r| r.lists.iter().any(|n| n == l)) {
            return Err(format!("list {l}: in no rule"));
        }
    }
    for (i, t) in tunnel_names.iter().enumerate() {
        if !rules.iter().any(|r| r.tunnels.contains(&i)) {
            return Err(format!("tunnel {t}: in no rule"));
        }
    }
    Ok(Settings {
        lists,
        tunnels,
        rules,
        degraded_grace,
    })
}

fn source(text: &str) -> Result<Source, &'static str> {
    if text.starts_with("https://") || text.starts_with("http://") {
        if text.chars().any(char::is_whitespace) {
            return Err("a URL has no spaces");
        }
        return Ok(Source::Url(text.to_owned()));
    }
    file(text).map(Source::File)
}

fn file(text: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(text);
    if text.is_empty() || !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err("a file is a path below the settings directory");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[list]]
name = "custom"
sources = ["lists/custom.lst"]

[[list]]
name = "telegram"
sources = [
  "https://example.org/Services/telegram.lst",
  "http://127.0.0.1:8765/telegram.lst",
]

[[list]]
name = "regional"
sources = ["https://example.org/Regional/outside-raw.lst"]

[[tunnel]]
name = "main"
conf = "main.conf"

[[tunnel]]
name = "backup"
conf = "tunnels/backup.conf"

[[tunnel]]
name = "other"
conf = "tunnels/other.conf"

[[rule]]
name = "pinned"
when = "always"
lists = ["custom"]
tunnels = ["main", "backup"]

[[rule]]
name = "bypass"
when = "DE"
lists = ["custom", "telegram"]
tunnels = ["main", "backup"]

[[rule]]
name = "abroad"
when = "!DE"
lists = ["regional"]
tunnels = ["other"]
"#;

    #[test]
    fn the_watchdog_settings_have_defaults() {
        assert_eq!(parse(GOOD).unwrap().degraded_grace, degraded::GRACE);
        let with = format!("[watch]\ndegraded_grace = 600\n{GOOD}");
        assert_eq!(
            parse(&with).unwrap().degraded_grace,
            Duration::from_mins(10)
        );
        // Zero is patience without end, not no patience at all.
        let none = format!("[watch]\ndegraded_grace = 0\n{GOOD}");
        assert_eq!(parse(&none).unwrap().degraded_grace, Duration::ZERO);
        // An empty table is the defaults; a key nobody knows is a mistake.
        assert_eq!(
            parse(&format!("[watch]\n{GOOD}")).unwrap().degraded_grace,
            degraded::GRACE
        );
        assert!(parse(&format!("[watch]\ngrace = 5\n{GOOD}")).is_err());
        assert!(parse(&format!("[watch]\ndegraded_grace = \"x\"\n{GOOD}")).is_err());
    }

    #[test]
    fn lists_tunnels_and_rules_in_order() {
        let s = parse(GOOD).unwrap();
        let names: Vec<&str> = s.lists.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["custom", "telegram", "regional"]);
        assert_eq!(
            s.lists[0].sources,
            [Source::File(PathBuf::from("lists/custom.lst"))]
        );
        assert_eq!(s.urls().count(), 3);
        assert_eq!(
            s.files().collect::<Vec<_>>(),
            [Path::new("lists/custom.lst")]
        );
        assert_eq!(s.tunnels[1].conf, PathBuf::from("tunnels/backup.conf"));
        let r: Vec<(&str, String, Vec<usize>)> = s
            .rules
            .iter()
            .map(|r| (r.name.as_str(), r.when.to_string(), r.tunnels.clone()))
            .collect();
        assert_eq!(
            r,
            [
                ("pinned", "always".to_owned(), vec![0, 1]),
                ("bypass", "DE".to_owned(), vec![0, 1]),
                ("abroad", "!DE".to_owned(), vec![2]),
            ]
        );
    }

    #[test]
    fn conditions() {
        assert!(When::Always.holds("DE"));
        assert!(When::In("DE".to_owned()).holds("DE"));
        assert!(!When::In("DE".to_owned()).holds("FR"));
        assert!(When::Out("DE".to_owned()).holds("FR"));
        assert!(!When::Out("DE".to_owned()).holds("DE"));
        for bad in ["de", "DEU", "!", "!de", "", "D", "never"] {
            assert_eq!(When::parse(bad), None, "{bad}");
        }
    }

    fn with(rules: &str) -> String {
        format!(
            "[[list]]\nname = \"a\"\nsources = [\"a.lst\"]\n\
             [[tunnel]]\nname = \"t\"\nconf = \"t.conf\"\n{rules}"
        )
    }

    const RULE: &str =
        "[[rule]]\nname = \"r\"\nwhen = \"always\"\nlists = [\"a\"]\ntunnels = [\"t\"]\n";

    #[test]
    fn refuses_bad_lists() {
        let one = |name: &str, src: &str| {
            format!("[[list]]\nname = \"{name}\"\nsources = [{src}]\n")
                + "[[tunnel]]\nname = \"t\"\nconf = \"t.conf\"\n"
                + &format!(
                    "[[rule]]\nname = \"r\"\nwhen = \"always\"\nlists = [\"{name}\"]\ntunnels = [\"t\"]\n"
                )
        };
        assert!(parse("").is_err());
        assert!(parse(&one("a-b_1", "\"x.lst\"")).is_ok());
        assert!(parse(&one("a b", "\"x.lst\"")).is_err());
        assert!(parse(&one("", "\"x.lst\"")).is_err());
        assert!(parse(&one("a", "")).is_err());
        assert!(parse(&one("a", "\"/etc/x.lst\"")).is_err());
        assert!(parse(&one("a", "\"../x.lst\"")).is_err());
        assert!(parse(&one("a", "\"./x.lst\"")).is_err());
        assert!(parse(&one("a", "\"https://a b\"")).is_err());
        assert!(parse(&(one("a", "\"x.lst\"") + "update = 1\n")).is_err());
        let twice = with(RULE) + "[[list]]\nname = \"a\"\nsources = [\"y.lst\"]\n";
        assert!(parse(&twice).unwrap_err().contains("named twice"));
    }

    #[test]
    fn refuses_bad_tunnels_and_rules() {
        assert!(parse(&with(RULE)).is_ok());
        assert!(parse(&with("")).unwrap_err().contains("no [[rule]]"));
        let bad = |rule: &str| parse(&with(rule)).unwrap_err();
        assert!(bad(&RULE.replace("always", "ru")).contains("when"));
        assert!(bad(&RULE.replace("[\"a\"]", "[]")).contains("no lists"));
        assert!(bad(&RULE.replace("[\"t\"]", "[]")).contains("no tunnels"));
        assert!(bad(&RULE.replace("[\"a\"]", "[\"b\"]")).contains("no list b"));
        assert!(bad(&RULE.replace("[\"t\"]", "[\"t\", \"t\"]")).contains("twice"));
        assert!(bad(&(RULE.to_owned() + RULE)).contains("named twice"));
        let unused = with(RULE) + "[[tunnel]]\nname = \"u\"\nconf = \"u.conf\"\n";
        assert!(parse(&unused).unwrap_err().contains("tunnel u: in no rule"));
        let unused = with(RULE) + "[[list]]\nname = \"b\"\nsources = [\"b.lst\"]\n";
        assert!(parse(&unused).unwrap_err().contains("list b: in no rule"));
        let same = with(RULE) + "[[tunnel]]\nname = \"u\"\nconf = \"t.conf\"\n";
        assert!(parse(&same).unwrap_err().contains("used twice"));
        let outside = with(RULE).replace("t.conf", "../t.conf");
        assert!(parse(&outside).is_err());
        assert!(parse(&(with(RULE) + "[[tunnel]]\nname = \"u\"\n")).is_err());
    }

    /// Every example in `examples/` passes what `install` checks before it
    /// changes anything, and every file there is used by some example.
    #[test]
    fn examples_are_valid() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
        let mut used = HashSet::new();
        let mut examples = 0;
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "toml") {
                continue;
            }
            let settings = load(&path).unwrap();
            crate::daemon::load_confs(&settings, &dir)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            used.extend(settings.tunnels.iter().map(|t| t.conf.clone()));
            for file in settings.files() {
                let text = fs::read_to_string(dir.join(file)).unwrap();
                let mut lists = crate::lists::Lists::default();
                lists.add("example", &text);
                assert!(
                    lists.rejected.is_empty(),
                    "{}: {:?}",
                    file.display(),
                    lists.rejected
                );
                assert!(crate::sources::check(&text).is_ok());
                used.insert(file.to_owned());
            }
            examples += 1;
        }
        assert!(examples > 0);
        for sub in ["lists", "tunnels"] {
            for entry in fs::read_dir(dir.join(sub)).unwrap() {
                let file = Path::new(sub).join(entry.unwrap().file_name());
                assert!(used.contains(&file), "{}: in no example", file.display());
            }
        }
    }
}
