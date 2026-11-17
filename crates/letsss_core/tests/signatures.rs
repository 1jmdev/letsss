use letsss_core::{
    Signatures,
    signatures::{Matcher, Settings, Subject},
};

fn hits(matcher: &Matcher, haystack: &[u8]) -> Vec<String> {
    let mut labels = Vec::new();
    matcher.scan(haystack, |hit| labels.push(hit.label.to_owned()));
    labels
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn database_decodes_and_every_rule_is_satisfiable() {
    let signatures = Signatures::load().expect("embedded database decodes");
    let database = &signatures.database;
    assert!(database.clients.len() > 100);
    for rule in &database.rules {
        let available = rule.strings.len() + rule.imports.len() + rule.sections.len();
        assert!(
            rule.minimum >= 1 && rule.minimum <= available,
            "rule {} is unsatisfiable",
            rule.tag
        );
    }
    for client in &database.clients {
        assert!(
            !client.strings.is_empty() || !client.domains.is_empty(),
            "client {} has no patterns",
            client.name
        );
    }
}

#[test]
fn client_patterns_match_dotted_and_utf16_forms() {
    let matcher = Matcher::new(
        [(Subject::Client(0), "net/ccbluex/liquidbounce")],
        Settings::default(),
    );
    assert_eq!(hits(&matcher, b"Lnet/ccbluex/liquidbounce/Main;").len(), 1);
    assert_eq!(hits(&matcher, b"at net.ccbluex.liquidbounce.Main").len(), 1);
    assert_eq!(hits(&matcher, &utf16("net.ccbluex.liquidbounce")).len(), 1);
}

#[test]
fn module_boundaries_accept_camel_case_and_reject_embedded_words() {
    let settings = Settings {
        case_insensitive: false,
        boundary: true,
        fullwidth: true,
    };
    let matcher = Matcher::new([(Subject::Module(0), "Reach")], settings);
    assert_eq!(hits(&matcher, b"module Reach enabled").len(), 1);
    assert_eq!(hits(&matcher, b"class ReachModule").len(), 1);
    assert!(hits(&matcher, b"getReach()").is_empty());
    assert!(hits(&matcher, b"module reach enabled").is_empty());
    assert!(hits(&matcher, b"the player reached the end").is_empty());
    assert!(hits(&matcher, b"overreach").is_empty());
    assert_eq!(hits(&matcher, "Ｒｅａｃｈ".as_bytes()).len(), 1);
    assert_eq!(hits(&matcher, &utf16("[Reach]")).len(), 1);
}

#[test]
fn domains_resolve_to_clients_including_subdomains() {
    let signatures = Signatures::load().expect("embedded database decodes");
    let database = &signatures.database;
    assert_eq!(
        database
            .client_for_domain("auth.vape.gg.")
            .map(|client| client.name.as_str()),
        Some("Vape V4")
    );
    assert!(database.client_for_domain("notvape.gg").is_none());
}
