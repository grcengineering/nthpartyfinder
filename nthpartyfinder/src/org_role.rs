//! Organization-role classification — the shared intermediary filter.
//!
//! Registrar-as-owner, privacy-proxy-as-owner, registry-as-owner and address-leak-as-owner
//! are one error class in four costumes: a string that names an *intermediary* rather than
//! the organization that actually owns the domain. Every attribution source can produce
//! them (WHOIS registrant fields, scraped pages, certificate subjects), so the filter lives
//! in one module and every source calls it.
//!
//! Two rules make this precise where the previous substring denylist was not:
//!
//! 1. **Matching is boundary-aware.** `contains("private")` rejected every Indian and
//!    British "… Private Limited" company; `contains("switch")` rejected Switch, Inc.
//!    (NYSE: SWCH); `contains("hover")` and `contains("donuts")` rejected any name
//!    containing those letters. Ambiguous single words are matched against the WHOLE
//!    cleaned name; only distinctive phrases are matched as word-bounded substrings.
//!
//! 2. **Self-attribution is never an intermediary.** GoDaddy *is* the owner of
//!    godaddy.com and Cloudflare *is* the owner of cloudflare.com. A name that shares a
//!    significant token with the domain it is being attributed to is the owner, not an
//!    intermediary, regardless of what the lists say.

use crate::domain_utils;

/// What an organization string actually names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgRole {
    /// A WHOIS privacy / redaction service ("Domains By Proxy", "REDACTED FOR PRIVACY").
    PrivacyService,
    /// A domain registrar or brand-protection agent ("MarkMonitor", "GoDaddy").
    Registrar,
    /// A TLD registry operator ("Verisign", "Nominet", "DENIC").
    RegistryOperator,
    /// A postal address or contact-form field leaking into the org field.
    AddressLeak,
    /// A real organization name.
    Valid,
}

impl OrgRole {
    /// Whether this role means "not the owner of the domain" — the single question every
    /// attribution source needs answered.
    pub fn is_intermediary(self) -> bool {
        !matches!(self, OrgRole::Valid)
    }
}

/// Names that are ONLY an intermediary when they are the entire organization string.
///
/// Each of these is either a common English word or a legitimate company name in its own
/// right, so a substring match on them is a false-reject generator. "Private" appears in
/// every "… Private Limited"; "Switch" is a listed company; "Donuts"/"Hover"/"Epik" are
/// registrars whose names are ordinary words.
const EXACT_INTERMEDIARY: &[(&str, OrgRole)] = &[
    ("private", OrgRole::PrivacyService),
    ("privado", OrgRole::PrivacyService),
    ("redacted", OrgRole::PrivacyService),
    ("withheld", OrgRole::PrivacyService),
    ("not disclosed", OrgRole::PrivacyService),
    ("not applicable", OrgRole::PrivacyService),
    ("n/a", OrgRole::PrivacyService),
    ("na", OrgRole::PrivacyService),
    ("none", OrgRole::PrivacyService),
    ("null", OrgRole::PrivacyService),
    ("unknown", OrgRole::PrivacyService),
    ("-", OrgRole::PrivacyService),
    ("switch", OrgRole::RegistryOperator),
    ("donuts", OrgRole::Registrar),
    ("hover", OrgRole::Registrar),
    ("epik", OrgRole::Registrar),
    ("registry operator", OrgRole::RegistryOperator),
];

/// Distinctive phrases that name an intermediary wherever they appear as whole words.
/// Every entry here is specific enough that it cannot be part of an unrelated company's
/// name (unlike "private" or "switch" above).
const PHRASE_INTERMEDIARY: &[(&str, OrgRole)] = &[
    // Privacy / redaction services
    ("domains by proxy", OrgRole::PrivacyService),
    // Nominee registrants — the most common strings in real WHOIS. Each stands in FOR the
    // owner, so each was being shipped as the owner: "DNStination Inc." is MarkMonitor's
    // nominee and appears on thousands of Fortune-500 domains; "Domain Protection Services,
    // Inc." is name.com's; "PrivacyGuardian.org" is NameSilo's; "Registration Private" is what
    // GoDaddy's Domains-By-Proxy puts in the Registrant Name field.
    ("dnstination", OrgRole::PrivacyService),
    ("domain protection services", OrgRole::PrivacyService),
    ("privacyguardian", OrgRole::PrivacyService),
    ("registration private", OrgRole::PrivacyService),
    ("whois agent", OrgRole::PrivacyService),
    ("whoisproxy", OrgRole::PrivacyService),
    ("domain admin", OrgRole::PrivacyService),
    // Word-bounded matching means "domain admin" does NOT match "Domain Administrator" (the
    // boundary check fails on the 'i'), and that longer form is what four vendor domains were
    // actually attributed to on a real scan. It is a role, not a company.
    ("domain administrator", OrgRole::PrivacyService),
    ("aruba pec", OrgRole::Registrar),
    ("wild west domains", OrgRole::Registrar),
    ("whoisguard", OrgRole::PrivacyService),
    ("whois privacy", OrgRole::PrivacyService),
    ("privacy protect", OrgRole::PrivacyService),
    ("privacy protection", OrgRole::PrivacyService),
    ("privacy service", OrgRole::PrivacyService),
    ("perfect privacy", OrgRole::PrivacyService),
    ("contact privacy", OrgRole::PrivacyService),
    ("redacted for privacy", OrgRole::PrivacyService),
    ("withheld for privacy", OrgRole::PrivacyService),
    ("identity protection service", OrgRole::PrivacyService),
    ("identity protect", OrgRole::PrivacyService),
    ("data protected", OrgRole::PrivacyService),
    ("statutory masking", OrgRole::PrivacyService),
    ("gdpr masked", OrgRole::PrivacyService),
    ("privacydotlink", OrgRole::PrivacyService),
    ("super privacy service", OrgRole::PrivacyService),
    // Registrars and brand-protection agents
    ("markmonitor", OrgRole::Registrar),
    ("csc corporate domains", OrgRole::Registrar),
    ("corporatedomains", OrgRole::Registrar),
    ("safenames", OrgRole::Registrar),
    ("com laude", OrgRole::Registrar),
    ("nameprotect", OrgRole::Registrar),
    ("brand protection", OrgRole::Registrar),
    ("domain management", OrgRole::Registrar),
    ("network solutions", OrgRole::Registrar),
    ("networksolutions", OrgRole::Registrar),
    ("godaddy", OrgRole::Registrar),
    ("namecheap", OrgRole::Registrar),
    ("namesilo", OrgRole::Registrar),
    ("enom", OrgRole::Registrar),
    ("tucows", OrgRole::Registrar),
    ("opensrs", OrgRole::Registrar),
    ("key-systems", OrgRole::Registrar),
    ("gandi", OrgRole::Registrar),
    ("porkbun", OrgRole::Registrar),
    ("dynadot", OrgRole::Registrar),
    ("register.com", OrgRole::Registrar),
    ("name.com", OrgRole::Registrar),
    ("domain.com", OrgRole::Registrar),
    ("amazon registrar", OrgRole::Registrar),
    ("google domains", OrgRole::Registrar),
    ("squarespace domains", OrgRole::Registrar),
    ("cloudflare registrar", OrgRole::Registrar),
    ("bluehost", OrgRole::Registrar),
    ("hostgator", OrgRole::Registrar),
    ("dreamhost", OrgRole::Registrar),
    ("siteground", OrgRole::Registrar),
    ("hostinger", OrgRole::Registrar),
    ("publicdomainregistry", OrgRole::Registrar),
    ("pdr ltd", OrgRole::Registrar),
    ("sav.com", OrgRole::Registrar),
    ("reg.ru", OrgRole::Registrar),
    ("ascio", OrgRole::Registrar),
    ("onlinenic", OrgRole::Registrar),
    ("todaynic", OrgRole::Registrar),
    ("xin net", OrgRole::Registrar),
    ("west263", OrgRole::Registrar),
    ("alibaba cloud computing", OrgRole::Registrar),
    ("gmo internet", OrgRole::Registrar),
    // Registry operators
    ("verisign", OrgRole::RegistryOperator),
    ("public interest registry", OrgRole::RegistryOperator),
    ("afilias", OrgRole::RegistryOperator),
    ("identity digital", OrgRole::RegistryOperator),
    ("centralnic", OrgRole::RegistryOperator),
    ("nominet", OrgRole::RegistryOperator),
    ("denic", OrgRole::RegistryOperator),
    ("afnic", OrgRole::RegistryOperator),
    ("icann", OrgRole::RegistryOperator),
    ("registro.br", OrgRole::RegistryOperator),
    ("registro.it", OrgRole::RegistryOperator),
    ("global registry services", OrgRole::RegistryOperator),
    ("domain name commission", OrgRole::RegistryOperator),
    ("domain administration", OrgRole::RegistryOperator),
    ("national internet exchange", OrgRole::RegistryOperator),
    // ccTLD registry operators. Many national registries answer WHOIS with THEMSELVES in the
    // registrant field ("Registrant: RoTLD" for a .ro domain), so without these a .ro vendor
    // would be attributed to Romania's registry. Each is distinctive enough to be word-bounded
    // safely — none is a plausible fragment of an unrelated company's name.
    ("rotld", OrgRole::RegistryOperator),
    ("nic.ro", OrgRole::RegistryOperator),
    ("nic.at", OrgRole::RegistryOperator),
    ("nic.br", OrgRole::RegistryOperator),
    ("eurid", OrgRole::RegistryOperator),
    ("dns belgium", OrgRole::RegistryOperator),
    ("dk hostmaster", OrgRole::RegistryOperator),
    ("punktum dk", OrgRole::RegistryOperator),
    ("internet stiftelsen", OrgRole::RegistryOperator),
    ("norid", OrgRole::RegistryOperator),
    ("cnnic", OrgRole::RegistryOperator),
    ("krnic", OrgRole::RegistryOperator),
    ("jprs", OrgRole::RegistryOperator),
    ("sgnic", OrgRole::RegistryOperator),
    ("twnic", OrgRole::RegistryOperator),
    ("hkirc", OrgRole::RegistryOperator),
    ("mynic", OrgRole::RegistryOperator),
    ("thnic", OrgRole::RegistryOperator),
    ("vnnic", OrgRole::RegistryOperator),
    ("sidn", OrgRole::RegistryOperator),
    ("nic.ch", OrgRole::RegistryOperator),
    ("nic.cz", OrgRole::RegistryOperator),
    ("nic.pl", OrgRole::RegistryOperator),
    ("nic.ir", OrgRole::RegistryOperator),
    ("nic.at", OrgRole::RegistryOperator),
    ("dns.pt", OrgRole::RegistryOperator),
    ("registry.in", OrgRole::RegistryOperator),
    ("nixi", OrgRole::RegistryOperator),
    (
        "national internet exchange of india",
        OrgRole::RegistryOperator,
    ),
    ("auda", OrgRole::RegistryOperator),
    (".au domain administration", OrgRole::RegistryOperator),
    ("nz domain name commission", OrgRole::RegistryOperator),
    ("cira", OrgRole::RegistryOperator),
    ("domaininfo.com", OrgRole::RegistryOperator),
    // Registries caught answering WHOIS with THEMSELVES on a real depth-3 scan. Each was shipped
    // as the owner of a vendor: together.ai -> "Government of Anguilla", wiz.io -> "Internet
    // Computer Bureau", baseten.co -> "Ministry of Information and Communications Technologies".
    // The registry that runs a TLD is never the owner of a domain registered under it.
    ("government of anguilla", OrgRole::RegistryOperator),
    ("internet computer bureau", OrgRole::RegistryOperator),
    (
        "ministry of information and communications technologies",
        OrgRole::RegistryOperator,
    ),
    ("mintic", OrgRole::RegistryOperator),
    // gTLD registry back-ends. These are the biggest single source of wrong owners on a real
    // scan, and their names give nothing away — you would have to know that "Charleston Road
    // Registry" is Google's registry for .dev and .app (43 vendor domains on one scan), that
    // "Binky Moon" and "Dog Beach" are Identity Digital's, and that "Radix" runs .tech and
    // .store. Every .dev vendor was being attributed to Charleston Road Registry.
    ("charleston road registry", OrgRole::RegistryOperator),
    ("binky moon", OrgRole::RegistryOperator),
    ("dog beach", OrgRole::RegistryOperator),
    ("radix technologies", OrgRole::RegistryOperator),
    ("radix fzc", OrgRole::RegistryOperator),
    ("neustar", OrgRole::RegistryOperator),
    // The word itself. A registrant field naming a "… Registry" is naming the operator of the
    // TLD, not the owner of the domain — and the operators keep inventing new brand names, so
    // matching the role beats chasing the names.
    ("registry", OrgRole::RegistryOperator),
    // Hosting/registrar groups that appear as the registrant of customer domains.
    ("ionos", OrgRole::Registrar),
    ("1&1 internet", OrgRole::Registrar),
    ("corporatedomains.com", OrgRole::Registrar),
    ("cloudflare", OrgRole::Registrar),
    // Address / contact-field leakage
    ("registrant street", OrgRole::AddressLeak),
    ("registrant city", OrgRole::AddressLeak),
    ("registrant state", OrgRole::AddressLeak),
    ("registrant postal", OrgRole::AddressLeak),
    ("registrant country", OrgRole::AddressLeak),
    ("registrant phone", OrgRole::AddressLeak),
    ("registrant email", OrgRole::AddressLeak),
    ("registrant fax", OrgRole::AddressLeak),
    ("admin street", OrgRole::AddressLeak),
    ("admin city", OrgRole::AddressLeak),
    ("tech street", OrgRole::AddressLeak),
    ("tech city", OrgRole::AddressLeak),
    ("po box", OrgRole::AddressLeak),
    ("p.o. box", OrgRole::AddressLeak),
    ("care of", OrgRole::AddressLeak),
];

/// Address words that make a leading digit an address rather than a company name.
/// `8x8`, `23andMe`, `1Password` and `3M` all start with a digit and are real companies —
/// a bare leading-digit rule rejects every one of them.
const ADDRESS_TOKENS: &[&str] = &[
    "street",
    "st.",
    "avenue",
    "ave",
    "ave.",
    "road",
    "rd.",
    "boulevard",
    "blvd",
    "blvd.",
    "suite",
    "ste.",
    "floor",
    "drive",
    "lane",
    "parkway",
    "pkwy",
    "highway",
    "box",
    "apt",
    "apartment",
];
// "way" and "unit" are deliberately absent. They are ordinary words in company names, and the
// rule that consumes this list only fires on a digit-leading name — which is exactly the shape
// of "1st Way Logistics" and "2 Way Communications Ltd". A street-address leak still has to
// carry one of the tokens above, and those are not company vocabulary.

/// Lowercase the name and strip the punctuation that separates legal suffixes, so
/// "Switch, Inc." and "switch inc" compare equal for the whole-string rules.
fn cleaned(org: &str) -> String {
    org.trim().to_lowercase()
}

/// The org string reduced to just its distinctive words: legal suffixes and punctuation
/// removed. Used for whole-string intermediary matching so "Switch, Inc." (a real company)
/// does not collapse onto the bare registry name "switch".
fn core_words(org: &str) -> Vec<String> {
    const LEGAL: &[&str] = &[
        "inc",
        "inc.",
        "llc",
        "llc.",
        "ltd",
        "ltd.",
        "limited",
        "corp",
        "corp.",
        "corporation",
        "co",
        "co.",
        "company",
        "gmbh",
        "plc",
        "ag",
        "sa",
        "bv",
        "nv",
        "s.a.",
        "s.r.l.",
        "pty",
        "pvt",
        "lp",
        "llp",
    ];
    cleaned(org)
        .split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '&')
        .map(|w| w.trim_matches(|c: char| c == '.' || c == ',').to_string())
        .filter(|w| !w.is_empty())
        .filter(|w| !LEGAL.contains(&w.as_str()))
        .collect()
}

/// Whether `phrase` occurs in `haystack` bounded by non-alphanumeric characters, so
/// "hover" does not match "Hoverboard Inc" and "private" does not match "Privateer".
fn contains_word_bounded(haystack: &str, phrase: &str) -> bool {
    let mut from = 0;
    while let Some(idx) = haystack[from..].find(phrase) {
        let start = from + idx;
        let end = start + phrase.len();
        let before_ok = start == 0
            || !haystack[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric());
        let after_ok = end == haystack.len()
            || !haystack[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        // Advance by one CHARACTER, not one byte — `start + 1` lands inside a multi-byte
        // character and panics on the next slice. The needles here are ASCII constants today,
        // so this is unreachable, but the same code in `subprocessor.rs` (where the needles are
        // learned from scraped text) was demonstrably crashable, and this copy must not become
        // the next instance.
        from = start + haystack[start..].chars().next().map_or(1, |c| c.len_utf8());
        if from >= haystack.len() {
            break;
        }
    }
    false
}

/// Whether an organization name plausibly names the owner of `domain` itself — the
/// self-attribution rescue. Cloudflare owns cloudflare.com; GoDaddy owns godaddy.com. A
/// significant word of the name matching the domain's registrable label means the name is
/// the owner, not an intermediary standing in front of one.
fn is_self_attribution(org: &str, domain: &str) -> bool {
    let base = domain_utils::extract_base_domain(domain);
    let Some(label) = base.split('.').next() else {
        return false;
    };
    let label = label.trim();
    if label.len() < 3 {
        return false;
    }
    let label = label.to_lowercase();

    // Words too generic to prove ownership on their own. Without this, "Domains By Proxy, LLC"
    // would be judged the rightful owner of proxy.com, and "Privacy Protection Service" the
    // owner of privacy.com (a real fintech) — the rescue would hand the domain straight back
    // to the intermediary it exists to filter out.
    const GENERIC: &[&str] = &[
        "domain",
        "domains",
        "privacy",
        "proxy",
        "network",
        "networks",
        "registry",
        "registrar",
        "protection",
        "service",
        "services",
        "hosting",
        "host",
        "internet",
        "web",
        "online",
        "digital",
        "identity",
        "global",
        "cloud",
        "solutions",
    ];

    let segments: Vec<String> = core_words(org)
        .iter()
        // A word may carry its own domain suffix ("GoDaddy.com, LLC"), so split each word on
        // dots too — otherwise "godaddy.com" never matches the label "godaddy" and the
        // registrar is judged an intermediary on its own domain.
        .flat_map(|word| word.split('.').map(str::to_string).collect::<Vec<_>>())
        // Compare on alphanumerics only, so "cloud-flare" matches "cloudflare".
        .map(|s| {
            s.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
        })
        .filter(|s| s.len() >= 3)
        .collect();

    // A single distinctive word matching the label.
    if segments
        .iter()
        .any(|s| *s == label && !GENERIC.contains(&s.as_str()))
    {
        return true;
    }

    // A multi-word name whose words CONCATENATE to the label: "Network Solutions, LLC" owns
    // networksolutions.com, "Identity Digital Inc." owns identitydigital.com. No single word
    // equals the label, so word-wise comparison alone judges each of these an intermediary
    // squatting on its own domain.
    segments
        .windows(2)
        .any(|w| format!("{}{}", w[0], w[1]) == label)
        || segments
            .windows(3)
            .any(|w| format!("{}{}{}", w[0], w[1], w[2]) == label)
}

/// Classify what an organization string names, in the context of the domain it is being
/// attributed to.
///
/// The domain matters: the same string is an intermediary on one domain and the rightful
/// owner on another. Pass the domain whenever it is known; use [`classify`] only when it
/// genuinely is not.
pub fn classify_for_domain(org: &str, domain: &str) -> OrgRole {
    let role = classify(org);

    // A redaction is never rescued by self-attribution. The rescue exists so that a real company
    // stays the owner of its own domain (GoDaddy owns godaddy.com) — but a redaction routinely
    // QUOTES the domain it is hiding: "On Behalf of Polytomic.Com Owner" shares its only
    // significant word with polytomic.com, so the rescue fired and shipped the redaction as the
    // company. The string still names nobody.
    if looks_like_redaction(&cleaned(org)) {
        return OrgRole::PrivacyService;
    }

    if role.is_intermediary() && is_self_attribution(org, domain) {
        return OrgRole::Valid;
    }
    role
}

/// A redaction by SHAPE rather than by name.
///
/// A denylist of privacy services can only ever name the ones somebody has already seen, and every
/// registrar words its redaction differently. But redactions share a shape: they describe the
/// registrant instead of naming them. A real depth-3 scan produced "On Behalf of Polytomic.Com
/// Owner", "Data Redacted" and "Registrant of vercel-storage.com" — none of which is on anyone's
/// list, and each of which shipped as a company name.
///
/// Note what these all have in common: they say "the owner of this domain" rather than saying who
/// the owner is. That is a description of ignorance, and the honest domain-derived label is
/// strictly better than any of them.
fn looks_like_redaction(lower: &str) -> bool {
    const REDACTION_SHAPES: &[&str] = &[
        "on behalf of",
        "data redacted",
        "data protected",
        "redacted for",
        "not disclosed",
        "non-public data",
        "gdpr",
        "statutory masking",
        "domain owner",
        "registrant of",
        "owner of ",
    ];
    if REDACTION_SHAPES.iter().any(|s| lower.contains(s)) {
        return true;
    }
    // "<something> Owner" / "<something> Registrant" — the field describes the role, not the name.
    let trimmed = lower.trim_end_matches(['.', ',', ' ']);
    trimmed.ends_with(" owner") || trimmed.ends_with(" registrant") || trimmed == "owner"
}

/// Classify an organization string with no domain context.
pub fn classify(org: &str) -> OrgRole {
    let lower = cleaned(org);
    if lower.is_empty() {
        return OrgRole::PrivacyService; // an empty registrant field is a redaction
    }

    if looks_like_redaction(&lower) {
        return OrgRole::PrivacyService;
    }

    // Whole-string rules first: these words are only intermediaries when they are the
    // ENTIRE name, never as a substring and never with a legal suffix attached.
    //
    // The legal suffix is the discriminator, not noise to be stripped: a registrant field
    // containing the bare word "Switch" is the Swiss registry, while "Switch, Inc." is the
    // Nasdaq-listed company. Likewise "Private" is a redaction and "Private Limited" is a
    // company. Comparing against the suffix-stripped form collapsed the two.
    // Trim ALL edge punctuation, not just dots and commas: a real scan produced the registrant
    // field "Not Disclosed!", whose exclamation mark was enough to walk straight past the
    // whole-string match and be reported as a company on seven vendor domains.
    let bare = lower.trim_matches(|c: char| !c.is_alphanumeric());
    if bare.is_empty() {
        // Nothing but punctuation ("-", "--", "."): an empty registrant field by another name.
        return OrgRole::PrivacyService;
    }
    for (needle, role) in EXACT_INTERMEDIARY {
        if bare == *needle {
            return *role;
        }
    }

    // Distinctive phrases, word-bounded.
    for (needle, role) in PHRASE_INTERMEDIARY {
        if contains_word_bounded(&lower, needle) {
            return *role;
        }
    }

    // Address leakage: a leading digit only means an address when an address word follows.
    if lower
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || c == '#')
        && lower
            .split_whitespace()
            .any(|w| ADDRESS_TOKENS.contains(&w.trim_matches(',')))
    {
        return OrgRole::AddressLeak;
    }

    OrgRole::Valid
}

/// Whether an organization string is unusable as the owner of `domain` — the single call
/// every attribution source makes before accepting a name.
pub fn is_intermediary_for_domain(org: &str, domain: &str) -> bool {
    classify_for_domain(org, domain).is_intermediary()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- The false-rejects the previous substring denylist produced ---

    #[test]
    fn private_limited_companies_are_valid_organizations() {
        // `contains("private")` rejected every Indian/UK "… Private Limited" company.
        assert_eq!(classify("Infosys Private Limited"), OrgRole::Valid);
        assert_eq!(classify("Tata Consultancy Private Ltd"), OrgRole::Valid);
        // A bare "private" registrant field is still a redaction.
        assert_eq!(classify("private"), OrgRole::PrivacyService);
        assert_eq!(classify("Private"), OrgRole::PrivacyService);
    }

    #[test]
    fn switch_inc_is_a_real_company_not_the_swiss_registry() {
        // NYSE: SWCH. `contains("switch")` rejected it.
        assert_eq!(classify("Switch, Inc."), OrgRole::Valid);
        assert_eq!(classify("Switch Communications"), OrgRole::Valid);
        // The bare registry name still classifies.
        assert_eq!(classify("switch"), OrgRole::RegistryOperator);
    }

    #[test]
    fn ordinary_words_that_are_registrar_names_do_not_match_as_substrings() {
        assert_eq!(classify("Hoverboard Technologies"), OrgRole::Valid);
        assert_eq!(classify("Donuts Delight Bakery LLC"), OrgRole::Valid);
        assert_eq!(classify("Epikurean Foods"), OrgRole::Valid);
    }

    #[test]
    fn digit_leading_company_names_are_valid() {
        // The bare leading-digit heuristic rejected all of these real companies.
        assert_eq!(classify("8x8, Inc."), OrgRole::Valid);
        assert_eq!(classify("23andMe Holding Co."), OrgRole::Valid);
        assert_eq!(classify("1Password"), OrgRole::Valid);
        assert_eq!(classify("3M Company"), OrgRole::Valid);
    }

    #[test]
    fn digit_leading_addresses_are_still_rejected() {
        assert_eq!(
            classify("5335 Gate Parkway, Suite 200"),
            OrgRole::AddressLeak
        );
        assert_eq!(classify("100 Main Street"), OrgRole::AddressLeak);
    }

    // --- Self-attribution: the owner of the registrar's own domain is the registrar ---

    #[test]
    fn a_multi_word_provider_owns_its_concatenated_domain() {
        // The self-attribution rescue compared each WORD of the name against the domain label,
        // so a provider whose label is its words run together matched nothing and was judged an
        // intermediary squatting on its own domain.
        for (org, domain) in [
            ("Network Solutions, LLC", "networksolutions.com"),
            ("Identity Digital Inc.", "identitydigital.com"),
            ("Alibaba Cloud Computing Ltd.", "alibabacloud.com"),
            ("Tucows Domains Inc.", "tucowsdomains.com"),
        ] {
            assert_eq!(
                classify_for_domain(org, domain),
                OrgRole::Valid,
                "{org} owns {domain} and must not be filtered out as an intermediary"
            );
        }
    }

    #[test]
    fn a_generic_word_does_not_hand_a_domain_to_an_intermediary() {
        // The rescue must not fire on a generic shared word: privacy.com is a real fintech, and
        // "Privacy Protection Service" appearing in its WHOIS does not make it the owner.
        assert!(is_intermediary_for_domain(
            "Domains By Proxy, LLC",
            "proxy.com"
        ));
        assert!(is_intermediary_for_domain(
            "Privacy Protection Service INC",
            "privacy.com"
        ));
    }

    #[test]
    fn nominee_registrants_are_not_owners() {
        // The most common real-world stand-ins. Each was classifying Valid and would have been
        // shipped as the owner of every domain whose registrant field it appears in.
        for org in [
            "DNStination Inc.",
            "Domain Protection Services, Inc.",
            "PrivacyGuardian.org",
            "Registration Private",
            "Whois Agent",
            "Wild West Domains, LLC",
        ] {
            assert!(
                is_intermediary_for_domain(org, "some-customer-domain.com"),
                "{org} stands in for the owner and must never be reported as one"
            );
        }
    }

    #[test]
    fn whois_garbage_observed_on_a_real_scan_is_never_an_owner() {
        // Every string here was produced by a real depth-3 scan of vanta.com and SHIPPED as the
        // organization owning a vendor's domain. They are the actual failure the user reported:
        // "lots of inaccurate domain to organization attribution". The honest domain-derived label
        // ("Together", "Wiz", "Polytomic") is strictly better than any of them.
        for (org, domain) in [
            // TLD registries answering with themselves.
            ("Government of Anguilla", "together.ai"),
            ("Internet Computer Bureau", "wiz.io"),
            (
                "Ministry of Information and Communications Technologies (MinTIC)",
                "baseten.co",
            ),
            // Redactions that describe the registrant instead of naming them.
            ("On Behalf of Polytomic.Com Owner", "polytomic.com"),
            (
                "On Behalf of Vercel-Storage.Com Owner",
                "vercel-storage.com",
            ),
            ("Data Redacted", "turbopuffer.com"),
            ("Not Disclosed!", "some-vendor.com"),
            // gTLD registry back-ends. On one scan these four alone claimed ~90 vendor domains.
            ("Charleston Road Registry", "some-tool.dev"),
            ("Binky Moon, LLC", "some-vendor.company"),
            ("Dog Beach, LLC", "some-vendor.games"),
            ("Radix Technologies", "some-vendor.tech"),
            ("Registry Services, LLC", "some-vendor.inc"),
        ] {
            assert!(
                is_intermediary_for_domain(org, domain),
                "{org:?} was shipped as the owner of {domain} on a real scan; it must be rejected"
            );
        }
    }

    #[test]
    fn a_redaction_is_recognised_by_shape_not_just_by_name() {
        // The denylist can only name the privacy services someone has already seen. The shape —
        // "the owner of this domain", said without naming them — generalizes to the ones we
        // haven't.
        assert_eq!(
            classify("On behalf of example.com owner"),
            OrgRole::PrivacyService
        );
        assert_eq!(classify("Domain Owner"), OrgRole::PrivacyService);
        assert_eq!(classify("Registrant of foo.net"), OrgRole::PrivacyService);
        assert_eq!(classify("Data Redacted"), OrgRole::PrivacyService);
        assert_eq!(classify("Non-Public Data"), OrgRole::PrivacyService);
        // ...and does not fire on real companies whose names merely contain those words.
        assert_eq!(classify("Owner Operator Direct, Inc."), OrgRole::Valid);
        assert_eq!(classify("Data Dog"), OrgRole::Valid);
        assert_eq!(classify("Redwood Materials"), OrgRole::Valid);
    }

    #[test]
    fn word_bounded_matching_does_not_panic_on_multibyte_names() {
        // `from = start + 1` advanced by one BYTE, so a needle beginning with a multi-byte
        // character sliced mid-character on the next iteration and panicked. Scraped vendor
        // names are routinely non-ASCII.
        assert!(!is_intermediary_for_domain(
            "xüber über gmbh",
            "example.com"
        ));
        assert!(!is_intermediary_for_domain(
            "Société Générale",
            "socgen.com"
        ));
        assert_eq!(classify("Ünïcodé Systems"), OrgRole::Valid);
    }

    #[test]
    fn digit_led_companies_with_way_or_unit_in_their_name_survive() {
        // "way" and "unit" were address tokens, and the address rule fires on digit-leading
        // names — exactly the shape of these two real companies.
        assert_eq!(classify("1st Way Logistics"), OrgRole::Valid);
        assert_eq!(classify("2 Way Communications Ltd"), OrgRole::Valid);
    }

    #[test]
    fn a_provider_is_the_valid_owner_of_its_own_domain() {
        assert_eq!(
            classify_for_domain("Cloudflare, Inc.", "cloudflare.com"),
            OrgRole::Valid
        );
        assert_eq!(
            classify_for_domain("GoDaddy.com, LLC", "godaddy.com"),
            OrgRole::Valid
        );
        assert_eq!(
            classify_for_domain("Verisign, Inc.", "verisign.com"),
            OrgRole::Valid
        );
        assert_eq!(
            classify_for_domain("MarkMonitor Inc.", "markmonitor.com"),
            OrgRole::Valid
        );
    }

    #[test]
    fn a_provider_on_someone_elses_domain_is_an_intermediary() {
        assert_eq!(
            classify_for_domain("MarkMonitor Inc.", "example.com"),
            OrgRole::Registrar
        );
        assert_eq!(
            classify_for_domain("Domains By Proxy, LLC", "example.com"),
            OrgRole::PrivacyService
        );
        assert!(is_intermediary_for_domain("GoDaddy.com, LLC", "acme.io"));
    }

    // --- The intermediary classes still classify ---

    #[test]
    fn privacy_services_classify() {
        assert_eq!(classify("REDACTED FOR PRIVACY"), OrgRole::PrivacyService);
        assert_eq!(
            classify("Withheld for Privacy ehf"),
            OrgRole::PrivacyService
        );
        assert_eq!(classify("Domains By Proxy, LLC"), OrgRole::PrivacyService);
        assert_eq!(classify("Contact Privacy Inc."), OrgRole::PrivacyService);
        assert_eq!(classify(""), OrgRole::PrivacyService);
    }

    #[test]
    fn registrars_classify() {
        assert_eq!(classify("MarkMonitor Inc."), OrgRole::Registrar);
        assert_eq!(classify("CSC Corporate Domains, Inc."), OrgRole::Registrar);
        assert_eq!(classify("NameCheap, Inc."), OrgRole::Registrar);
        assert_eq!(classify("NameSilo, LLC"), OrgRole::Registrar);
    }

    #[test]
    fn registry_operators_classify() {
        assert_eq!(classify("Nominet UK"), OrgRole::RegistryOperator);
        assert_eq!(classify("DENIC eG"), OrgRole::RegistryOperator);
        assert_eq!(
            classify("Public Interest Registry"),
            OrgRole::RegistryOperator
        );
    }

    #[test]
    fn cctld_registries_that_name_themselves_as_registrant_classify() {
        // National registries routinely answer WHOIS with THEMSELVES in the registrant field:
        // a .ro lookup returns "Registrant: RoTLD". Without these entries, every Romanian
        // vendor in a scan would be attributed to Romania's domain registry.
        for org in ["RoTLD", "NIC.RO", "EURid vzw", "DK Hostmaster A/S", "JPRS"] {
            assert_eq!(
                classify(org),
                OrgRole::RegistryOperator,
                "{org} should be classified as a registry operator"
            );
        }
    }

    #[test]
    fn ordinary_vendors_are_valid() {
        for org in [
            "Stripe, Inc.",
            "Twilio Inc.",
            "Datadog, Inc.",
            "The Trade Desk, Inc.",
            "Bank of America Corporation",
            "Amazon Web Services, Inc.",
        ] {
            assert_eq!(classify(org), OrgRole::Valid, "org: {org}");
        }
    }

    #[test]
    fn word_boundary_matching_is_exact() {
        assert!(contains_word_bounded("markmonitor inc", "markmonitor"));
        assert!(!contains_word_bounded("privateer holdings", "private"));
        assert!(contains_word_bounded(
            "domains by proxy, llc",
            "domains by proxy"
        ));
    }

    #[test]
    fn is_intermediary_maps_every_non_valid_role() {
        assert!(OrgRole::PrivacyService.is_intermediary());
        assert!(OrgRole::Registrar.is_intermediary());
        assert!(OrgRole::RegistryOperator.is_intermediary());
        assert!(OrgRole::AddressLeak.is_intermediary());
        assert!(!OrgRole::Valid.is_intermediary());
    }
}
