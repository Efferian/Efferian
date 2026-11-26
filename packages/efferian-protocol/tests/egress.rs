use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use efferian_protocol::*;
use ipnet::IpNet;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn all_policy_ranges_match_network_boundaries() -> Result {
    let ranges = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "::/96",
        "::ffff:0:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:db8::/32",
        "2001:10::/28",
        "2001::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    ]
    .map(str::parse::<IpNet>)
    .into_iter()
    .collect::<std::result::Result<Vec<_>, _>>()?;
    for net in &ranges {
        for bound in [net.network(), net.broadcast()] {
            assert!(!is_globally_routable_ip(bound), "{net}: {bound}");
        }
        for neighbor in [
            adjacent(net.network(), false),
            adjacent(net.broadcast(), true),
        ]
        .into_iter()
        .flatten()
        {
            let expected = !ranges
                .iter()
                .any(|net| net.contains(&canonicalize_ip(neighbor)));
            assert_eq!(
                is_globally_routable_ip(neighbor),
                expected,
                "{neighbor} adjacent to {net}"
            );
        }
    }
    for public in ["8.8.8.8", "2606:4700:4700::1111"] {
        assert!(is_globally_routable_ip(public.parse()?));
    }
    Ok(())
}

fn adjacent(ip: IpAddr, higher: bool) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(addr) => {
            let bits = addr.to_bits();
            let bits = if higher {
                bits.checked_add(1)
            } else {
                bits.checked_sub(1)
            }?;
            Some(Ipv4Addr::from_bits(bits).into())
        }
        IpAddr::V6(addr) => {
            let bits = addr.to_bits();
            let bits = if higher {
                bits.checked_add(1)
            } else {
                bits.checked_sub(1)
            }?;
            Some(Ipv6Addr::from_bits(bits).into())
        }
    }
}

#[test]
fn cidr_opt_in_preserves_native_and_mapped_parity() -> Result {
    let native = EgressPolicy::from_cidrs(&["10.20.30.42/24"], false)?;
    let mapped = EgressPolicy::from_cidrs(&["::ffff:10.20.30.42/120"], false)?;
    let all_v6 = EgressPolicy::from_cidrs(&["::/0"], false)?;
    assert_eq!(native, mapped);
    assert_eq!(
        native.allowed_egress_cidrs(),
        &["10.20.30.0/24".parse::<IpNet>()?]
    );
    for (mapped, canonical) in [
        ("::ffff:127.0.0.1/96", "0.0.0.0/0"),
        ("::ffff:127.0.0.1/128", "127.0.0.1/32"),
    ] {
        assert_eq!(
            EgressPolicy::from_cidrs(&[mapped], false)?,
            EgressPolicy::from_cidrs(&[canonical], false)?
        );
    }
    assert_eq!(
        EgressPolicy::from_cidrs(&["10.0.0.0/8", "::ffff:127.0.0.1/95"], false),
        Err(SsrfError::InvalidCidr)
    );

    for (raw, plain, opted_in) in [
        ("10.20.30.42", false, true),
        ("10.20.31.42", false, false),
        ("8.8.8.8", true, true),
    ] {
        let ip: Ipv4Addr = raw.parse()?;
        for (policy, allowed) in [
            (&EgressPolicy::default(), plain),
            (&native, opted_in),
            (&mapped, opted_in),
            (&all_v6, plain),
        ] {
            assert_eq!(is_allowed_egress_ip(ip.into(), policy), allowed, "{ip}");
            assert_eq!(
                is_allowed_egress_ip(ip.to_ipv6_mapped().into(), policy),
                allowed,
                "{ip}"
            );
        }
    }
    assert!(is_allowed_egress_ip("fc00::1".parse()?, &all_v6));
    Ok(())
}

#[test]
fn egress_url_rejects_bad_authority_before_ip_policy() -> Result {
    use EgressUrlMode::Plain;
    let policy = EgressPolicy::default();
    for (url, ip) in [
        ("http://127.0.0.1/", "127.0.0.1"),
        ("http://127.1/", "127.0.0.1"),
        ("http://2130706433/", "127.0.0.1"),
        ("http://[::ffff:127.0.0.1]/", "127.0.0.1"),
        ("http://[fe80::42]/", "fe80::42"),
        ("http://[fc00::1]/", "fc00::1"),
        ("http://[64:ff9b::7f00:1]/", "64:ff9b::7f00:1"),
    ] {
        assert_eq!(
            validate_egress_url(url, &policy, Plain),
            Err(SsrfError::DisallowedIp(ip.parse()?)),
            "{url}"
        );
    }
    for (url, error) in [
        ("http://@127.0.0.1/", SsrfError::UserinfoForbidden),
        ("http://user:pass@127.0.0.1/", SsrfError::UserinfoForbidden),
        ("http://[fe80::1%25lan0]/", SsrfError::Ipv6ZoneIdForbidden),
        ("http://[fe80::1%lan0]/", SsrfError::Ipv6ZoneIdForbidden),
        ("http://%31%32%37.0.0.1/", SsrfError::Ipv6ZoneIdForbidden),
        ("https:///example.org/", SsrfError::MissingHost),
        ("https://?a=x", SsrfError::MissingHost),
        ("https:/example.org/", SsrfError::InvalidUrl),
        ("http://example.org\\@127.0.0.1/", SsrfError::InvalidUrl),
        ("http://127.0.0.1/#end", SsrfError::FragmentForbidden),
        ("file:///tmp/test", SsrfError::InvalidScheme),
        (" https://example.org", SsrfError::InvalidUrl),
        ("https://exam\nple.org", SsrfError::InvalidUrl),
        ("https://example.org/\x7f", SsrfError::InvalidUrl),
    ] {
        assert_eq!(
            validate_egress_url(url, &policy, Plain),
            Err(error),
            "{url}"
        );
    }
    for url in [
        "HTTP://example.org/a@b?q=%40",
        "https://example.org/a%2Fb?q=a@b",
        "https://8.8.8.8/",
    ] {
        assert!(validate_egress_url(url, &policy, Plain).is_ok(), "{url}");
    }
    Ok(())
}

#[test]
fn tls_opt_in_and_cidr_opt_in_are_independent() -> Result {
    use EgressUrlMode::{Plain, RequireHttpsByDefault};
    let default = EgressPolicy::default();
    let insecure = EgressPolicy::from_cidrs(&[], true)?;
    let addresses = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"];
    let allowed = EgressPolicy::from_cidrs(&addresses, false)?;
    let allowed_insecure = EgressPolicy::from_cidrs(&addresses, true)?;

    for host in ["127.0.0.1", "[::ffff:127.0.0.1]", "[::1]"] {
        let raw = format!("http://{host}/");
        for disallowed in [&default, &insecure] {
            assert!(matches!(
                validate_egress_url(&raw, disallowed, RequireHttpsByDefault),
                Err(SsrfError::DisallowedIp(_))
            ));
        }
        assert!(
            validate_egress_url(&raw, &allowed, RequireHttpsByDefault).is_ok(),
            "{host}"
        );
    }
    for host in [
        "10.0.0.1",
        "8.8.8.8",
        "localhost",
        "localhost.",
        "service.localhost",
        "example.org",
    ] {
        let raw = format!("http://{host}/");
        assert_eq!(
            validate_egress_url(&raw, &allowed, RequireHttpsByDefault),
            Err(SsrfError::InsecureHttpForbidden),
            "{host}"
        );
        assert!(validate_egress_url(&raw, &allowed, Plain).is_ok(), "{host}");
        assert!(
            validate_egress_url(&raw, &allowed_insecure, RequireHttpsByDefault).is_ok(),
            "{host}"
        );
    }
    assert!(validate_egress_url("https://example.org", &default, RequireHttpsByDefault).is_ok());
    assert!(matches!(
        validate_egress_url("http://10.0.0.1", &default, Plain),
        Err(SsrfError::DisallowedIp(_))
    ));
    Ok(())
}

#[test]
fn http_segments_keep_base_path_and_query_boundaries() -> Result {
    let policy = EgressPolicy::default();
    for bad in [
        "", ".", "..", "a/b", "a\\b", "a;b", "a%2fb", "a?b", "a#b", "a\0b", "\t",
    ] {
        assert!(validate_http_path_segment(bad).is_err(), "{bad:?}");
    }
    for (path, expected) in [
        ("/", "/items"),
        ("/api", "/api/items"),
        ("/api/", "/api/items"),
        ("/a//b/", "/a//b/items"),
        ("/a%2Fb/", "/a%2Fb/items"),
        ("/a//", "/a//items"),
    ] {
        let base = validate_http_base_url(&format!("https://example.org{path}"), &policy, false)?;
        assert_eq!(
            resolve_http_url(&base, &["items".into()], &BTreeMap::new())?.path(),
            expected
        );
        let same = resolve_http_url(&base, &[], &BTreeMap::new())?;
        assert_eq!(same.path(), path);
        assert_eq!(same.query(), None);
    }
    let base = validate_http_base_url("https://example.org/api/", &policy, false)?;
    let url = resolve_http_url(
        &base,
        &["a b".into()],
        &BTreeMap::from([("q".into(), "a b".into())]),
    )?;
    assert_eq!(url.as_str(), "https://example.org/api/a%20b?q=a+b");
    let url = resolve_http_url(&base, &[], &BTreeMap::from([("q".into(), "v".into())]))?;
    assert_eq!(url.as_str(), "https://example.org/api/?q=v");
    let url = resolve_http_url(&base, &["ä文".into()], &BTreeMap::new())?;
    assert_eq!(url.as_str(), "https://example.org/api/%C3%A4%E6%96%87");
    assert!(validate_http_base_url("https://example.org/api?from=base", &policy, false).is_err());
    Ok(())
}
