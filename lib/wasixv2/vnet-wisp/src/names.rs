//! Names resolved by the WISP server, not the guest: each name the guest looks up gets an
//! address of its own from RFC 2544's benchmarking range, as fake-IP DNS proxies hand out, and
//! a connection to that address asks the server for the name. The server's resolver then picks
//! the address, so names behind CDNs and split-horizon DNS work as they do in a browser.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use wasixv2_vnet::{Answer, Found, Lookup, LookupError};

/// 198.18.0.0/15.
const FIRST: u32 = u32::from_be_bytes([198, 18, 0, 1]);
const LAST: u32 = u32::from_be_bytes([198, 19, 255, 254]);
/// How long the guest may keep an answer; the address stays the name's for the backend's life.
const TTL: u32 = 300;
/// How long the guest may remember that an address has no name.
const NEGATIVE_TTL: u32 = 5;

#[derive(Default)]
pub(crate) struct Names {
    by_name: HashMap<String, Ipv4Addr>,
    by_addr: HashMap<Ipv4Addr, String>,
}

impl Names {
    pub(crate) fn lookup(&mut self, lookup: &Lookup) -> Result<Found, LookupError> {
        let answer = match lookup {
            Lookup::Name(name) => Answer::Addrs {
                canonical: name.clone(),
                addrs: vec![IpAddr::V4(self.address_of(name)?)],
            },
            Lookup::Addr(IpAddr::V4(addr)) if is_fake(*addr) => Answer::Name(
                self.by_addr
                    .get(addr)
                    .cloned()
                    .ok_or(LookupError::NotFound { ttl: NEGATIVE_TTL })?,
            ),
            Lookup::Addr(_) => return Err(LookupError::NotFound { ttl: NEGATIVE_TTL }),
            // Other record types need a real resolver, which a WISP server does not offer.
            Lookup::Forward(_) => return Err(LookupError::Failed),
        };
        Ok(Found { answer, ttl: TTL })
    }

    /// What to ask the WISP server for to reach `addr`: the name behind a fake address, the
    /// address itself otherwise. `None` for a fake address no lookup handed out.
    pub(crate) fn host_for(&self, addr: IpAddr) -> Option<String> {
        match addr {
            IpAddr::V4(v4) if is_fake(v4) => self.by_addr.get(&v4).cloned(),
            other => Some(other.to_string()),
        }
    }

    fn address_of(&mut self, name: &str) -> Result<Ipv4Addr, LookupError> {
        let name = name.to_ascii_lowercase();
        if let Some(addr) = self.by_name.get(&name) {
            return Ok(*addr);
        }
        let next = FIRST + self.by_name.len() as u32;
        if next > LAST {
            return Err(LookupError::Failed);
        }
        let addr = Ipv4Addr::from(next);
        self.by_name.insert(name.clone(), addr);
        self.by_addr.insert(addr, name);
        Ok(addr)
    }
}

fn is_fake(addr: Ipv4Addr) -> bool {
    (FIRST..=LAST).contains(&u32::from(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr_of(names: &mut Names, name: &str) -> IpAddr {
        match names.lookup(&Lookup::Name(name.into())).unwrap().answer {
            Answer::Addrs { addrs, .. } => addrs[0],
            other => panic!("not an address answer: {other:?}"),
        }
    }

    #[test]
    fn a_name_keeps_its_address_and_leads_back_to_itself() {
        let mut names = Names::default();
        let a = addr_of(&mut names, "Example.com");
        let b = addr_of(&mut names, "wasmer.io");

        assert_eq!(a, IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)));
        assert_ne!(a, b);
        assert_eq!(addr_of(&mut names, "example.com"), a);
        assert_eq!(names.host_for(a).as_deref(), Some("example.com"));
        assert_eq!(
            names.lookup(&Lookup::Addr(b)).unwrap().answer,
            Answer::Name("wasmer.io".into())
        );
    }

    #[test]
    fn real_addresses_go_to_the_server_as_they_are() {
        let names = Names::default();
        assert_eq!(
            names.host_for("127.0.0.1".parse().unwrap()).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            names.host_for("2001:db8::1".parse().unwrap()).as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn what_no_lookup_handed_out_is_not_found() {
        let mut names = Names::default();
        let unknown = IpAddr::V4(Ipv4Addr::new(198, 18, 4, 4));
        assert_eq!(names.host_for(unknown), None);
        assert_eq!(
            names.lookup(&Lookup::Addr(unknown)),
            Err(LookupError::NotFound { ttl: NEGATIVE_TTL })
        );
        assert_eq!(
            names.lookup(&Lookup::Forward(vec![0; 12])),
            Err(LookupError::Failed)
        );
    }
}
