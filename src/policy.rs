//! The policy: deny-overrides, deny-by-default, and a third answer for "make it safe".
//!
//! Order-dependent allow-lists are how people ship holes: someone inserts an `allow` above the
//! `deny` that was protecting a pump, and nothing complains. Here **a `deny` line wins over every
//! `allow` line regardless of position**, and no matching line at all is a denial.
//!
//! ```text
//! allow fc in {3,4} addr 0..499 role reader
//! allow fc 6 addr 40001..40010 role operator value in 0..1000
//! allow fc in {5,15} addr 0..99 role supervisor dual
//! deny  fc in {5,6} addr 0..99            # emergency stop wiring: never by wire
//! safe  fc 6 addr 500..599                # on refusal, drive this range to its safe value
//! ```
//!
//! The third answer matters as much as the first two. "Deny" leaves the process exactly as it was,
//! which is the right answer for a read and the wrong answer for an output that is now in a state it
//! must not stay in. `safe` names those ranges: a refused write there is not dropped, it is replaced
//! by the safe value, and the substitution is written to the audit log.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Reader = 0,
    Operator = 1,
    Supervisor = 2,
}

impl Role {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "reader" => Some(Role::Reader),
            "operator" => Some(Role::Operator),
            "supervisor" => Some(Role::Supervisor),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub fc: u8,
    pub unit: u8,
    pub addr: u16,
    pub qty: u16,
    pub value: Option<u16>,
    pub role: Role,
}

/// What the guard decided, before anything reaches the PLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Pass it through. `dual` means a second signature must also verify.
    Allow { dual: bool },
    /// Do not touch the PLC.
    Deny(&'static str),
    /// Do not apply the request, but drive the affected outputs to their safe values.
    Safe(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub line: usize,
    pub reason: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy line {}: {}", self.line, self.reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Allow,
    Deny,
    Safe,
}

#[derive(Debug, Clone)]
struct Rule {
    kind: Kind,
    functions: Vec<u8>,
    units: Option<Vec<u8>>,
    address: Option<(u16, u16)>,
    role: Option<Role>,
    value: Option<(u16, u16)>,
    dual: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    rules: Vec<Rule>,
}

#[cfg(kani)]
impl Rule {
    /// Правило без разбора текста — только для kani-харнессов.
    pub(crate) fn for_proof(
        kind: Kind,
        functions: Vec<u8>,
        address: Option<(u16, u16)>,
        role: Option<Role>,
        dual: bool,
    ) -> Self {
        Self {
            kind,
            functions,
            units: None,
            address,
            role,
            value: None,
            dual,
        }
    }
}

#[cfg(kani)]
impl Policy {
    /// Политика из готовых правил, без разбора строки.
    ///
    /// Зачем: под CBMC разбор текста раскручивает `memchr` внутри `str::lines/split` на тысячи
    /// итераций, и доказательство `evaluate` не закрывалось вовсе. Сам парсер проверяется
    /// обычными тестами (`policy::tests`), харнесс же должен рассуждать о `evaluate`.
    pub(crate) fn for_proof(rules: Vec<Rule>) -> Self {
        Self { rules }
    }
}

impl Policy {
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let mut rules = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            rules.push(parse_rule(line).map_err(|reason| PolicyError {
                line: index + 1,
                reason,
            })?);
        }
        if rules.is_empty() {
            return Err(PolicyError {
                line: 0,
                reason: "the policy has no rules, so nothing would ever be allowed".into(),
            });
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> usize {
        self.rules.len()
    }

    /// Deny-overrides: a denial anywhere beats an allowance anywhere.
    pub fn evaluate(&self, request: &Request) -> Verdict {
        let mut allowed: Option<bool> = None; // Some(dual) when an allow line matched
        let mut safe_match = false;
        for rule in &self.rules {
            if !rule.matches(request) {
                continue;
            }
            match rule.kind {
                Kind::Deny => return Verdict::Deny("deny-overrides: an explicit denial matched"),
                Kind::Safe => safe_match = true,
                Kind::Allow => {
                    allowed = Some(allowed.unwrap_or(false) || rule.dual);
                }
            }
        }
        if let Some(dual) = allowed {
            return Verdict::Allow { dual };
        }
        if safe_match {
            return Verdict::Safe("the policy names this range as one to drive safe on refusal");
        }
        Verdict::Deny("deny-by-default: no rule allows this request")
    }
}

fn parse_rule(line: &str) -> Result<Rule, String> {
    let mut words = line.split_whitespace();
    let kind = match words.next().ok_or("empty rule")? {
        "allow" => Kind::Allow,
        "deny" => Kind::Deny,
        "safe" => Kind::Safe,
        other => return Err(format!("{other:?} is not allow, deny or safe")),
    };
    let mut rule = Rule {
        kind,
        functions: Vec::new(),
        units: None,
        address: None,
        role: None,
        value: None,
        dual: false,
    };
    let words: Vec<&str> = words.collect();
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        match word {
            "dual" => {
                rule.dual = true;
                index += 1;
            }
            "fc" => {
                index += 1;
                let (values, used) = parse_u8_set(&words[index..])?;
                rule.functions = values;
                index += used;
            }
            "unit" => {
                index += 1;
                let (values, used) = parse_u8_set(&words[index..])?;
                rule.units = Some(values);
                index += used;
            }
            "addr" => {
                index += 1;
                let text = words.get(index).ok_or("addr needs a value or a range")?;
                rule.address = Some(parse_range(text)?);
                index += 1;
            }
            "role" => {
                index += 1;
                let text = words.get(index).ok_or("role needs a name")?;
                rule.role =
                    Some(Role::parse(text).ok_or_else(|| {
                        format!("{text:?} is not reader, operator or supervisor")
                    })?);
                index += 1;
            }
            "value" => {
                index += 1;
                let text = words.get(index).ok_or("value needs a number or a range")?;
                rule.value = Some(parse_range(text)?);
                index += 1;
            }
            other => return Err(format!("{other:?} is not a word this policy understands")),
        }
    }
    if rule.functions.is_empty() {
        return Err("a rule without `fc` would match every function code".into());
    }
    Ok(rule)
}

/// `fc 3`, `fc in {3,4}` or `fc in {1,2,3}`.
fn parse_u8_set(words: &[&str]) -> Result<(Vec<u8>, usize), String> {
    let first = words.first().ok_or("expected a number or `in`")?;
    if *first == "in" {
        let set = words.get(1).ok_or("`in` needs a set like {3,4}")?;
        let inner = set
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or("a set is written {3,4}")?;
        let mut values = Vec::new();
        for item in inner.split(',') {
            values.push(
                item.trim()
                    .parse::<u8>()
                    .map_err(|_| format!("{item:?} is not a number"))?,
            );
        }
        if values.is_empty() {
            return Err("an empty set matches nothing".into());
        }
        Ok((values, 2))
    } else {
        let value = first
            .parse::<u8>()
            .map_err(|_| format!("{first:?} is not a number"))?;
        Ok((vec![value], 1))
    }
}

fn parse_range(text: &str) -> Result<(u16, u16), String> {
    match text.split_once("..") {
        Some((low, high)) => {
            let low: u16 = low
                .parse()
                .map_err(|_| format!("{low:?} is not a number"))?;
            let high: u16 = high
                .parse()
                .map_err(|_| format!("{high:?} is not a number"))?;
            if low > high {
                return Err(format!("range {low}..{high} is backwards"));
            }
            Ok((low, high))
        }
        None => {
            let value: u16 = text
                .parse()
                .map_err(|_| format!("{text:?} is not a number or a range"))?;
            Ok((value, value))
        }
    }
}

impl Rule {
    fn matches(&self, request: &Request) -> bool {
        if !self.functions.contains(&request.fc) {
            return false;
        }
        if let Some(units) = &self.units {
            if !units.contains(&request.unit) {
                return false;
            }
        }
        if let Some(role) = self.role {
            if request.role < role {
                return false;
            }
        }
        if let Some((low, high)) = self.address {
            // The whole requested span must sit inside the rule's span: a rule for 40001..40010 must
            // not authorise a write that starts at 40001 and runs to 40060.
            let end = request.addr.saturating_add(request.qty.saturating_sub(1));
            if request.addr < low || end > high {
                return false;
            }
        }
        if let Some((low, high)) = self.value {
            match request.value {
                Some(value) if value >= low && value <= high => {}
                Some(_) => return false,
                None => return false,
            }
        }
        true
    }
}
