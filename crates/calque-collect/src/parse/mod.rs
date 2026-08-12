//! Parseurs des sorties de commandes — modules PURS, testés sur les
//! transcripts enregistrés de `corpus/collect/` (aucun réseau requis).

pub mod cisco;
pub mod fortigate;

use calque_model::{DeviceId, Endpoint, IfaceId, Link, LinkOrigin};

/// Un voisin vu par LLDP ou CDP, extrémités déjà normalisées
/// ([`crate::ifname`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Neighbor {
    /// Le port LOCAL (sur l'équipement collecté), nom normalisé.
    pub local_iface: String,
    /// L'identifiant de l'équipement distant, normalisé (nom court).
    pub remote_device: String,
    /// Le port DISTANT, nom normalisé.
    pub remote_iface: String,
}

/// Le résultat d'un parseur de voisinage : les voisins compris, et les
/// avertissements pour ce qui ne l'a pas été (§6.3 : rien n'est ignoré
/// en silence).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedNeighbors {
    pub neighbors: Vec<Neighbor>,
    pub warnings: Vec<String>,
}

/// Convertit des voisins en liens de topologie (`LinkOrigin::Lldp`),
/// dédupliqués et triés. `local` est l'identifiant de l'équipement
/// collecté dans le modèle.
pub fn neighbors_to_links(local: &DeviceId, neighbors: &[Neighbor]) -> Vec<Link> {
    let mut links: Vec<Link> = neighbors
        .iter()
        .map(|n| Link {
            a: Endpoint {
                device: local.clone(),
                iface: IfaceId::new(n.local_iface.as_str()),
            },
            b: Endpoint {
                device: DeviceId::new(n.remote_device.as_str()),
                iface: IfaceId::new(n.remote_iface.as_str()),
            },
            origin: LinkOrigin::Lldp,
        })
        .collect();
    links.sort();
    links.dedup();
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liens_dedupliques_lldp_et_cdp_confondus() {
        // Le même lien vu par LLDP et par CDP ne doit compter qu'une fois.
        let n = Neighbor {
            local_iface: "GigabitEthernet0/1".into(),
            remote_device: "sw-01".into(),
            remote_iface: "GigabitEthernet0/24".into(),
        };
        let links = neighbors_to_links(&DeviceId::new("fw-01"), &[n.clone(), n]);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].origin, LinkOrigin::Lldp);
        assert_eq!(links[0].a.device.as_str(), "fw-01");
        assert_eq!(links[0].b.iface.as_str(), "GigabitEthernet0/24");
    }
}
