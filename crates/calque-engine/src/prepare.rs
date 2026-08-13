//! Préparation d'un modèle pour le moteur : accrochage des politiques à
//! couple de zones. À appeler UNE FOIS sur le `Network` avant `trace_packet`,
//! `reach_to`/`reach_from` ou `calque_diff::plan` — c'est le point de
//! jonction des consommateurs en bibliothèque (la CLI et Constat passent
//! par la même préparation).

use calque_model::Network;

/// Choix documenté — accrochage des politiques à couple de zones.
///
/// L'adaptateur FortiGate accroche la politique `forward` en entrée
/// (`Pipeline::ingress`), mais ses règles contraignent un couple de zones
/// (`from`, `to`). Or la zone de SORTIE n'est connue qu'après la décision
/// de routage : le moteur, qui ne devine jamais, refuse d'évaluer une
/// contrainte `to` au point d'entrée (`EgressZoneUnknownAtIngress`).
///
/// Sur l'équipement réel, la politique forward est bel et bien consultée
/// APRÈS la recherche de route (la décision dépend de l'interface de
/// sortie). Évaluer ces politiques au point de sortie — où le moteur
/// conserve la zone d'entrée ET connaît la zone de sortie — reproduit donc
/// exactement la sémantique constructeur, sans rien supposer. On déplace
/// ici, sur une COPIE du modèle et uniquement pour l'évaluation, toute
/// politique d'entrée dont au moins une règle contraint la zone de sortie.
///
/// La fonction est idempotente : sur un modèle déjà préparé, elle ne
/// change plus rien. L'ordre relatif des politiques est préservé (les
/// politiques déplacées passaient avant les politiques de sortie
/// existantes : elles restent devant) ; ni les règles ni leur ordre ne
/// sont modifiés.
pub fn prepare_for_engine(network: &Network) -> Network {
    let mut network = network.clone();
    for device in network.devices.values_mut() {
        let (to_egress, keep_ingress): (Vec<_>, Vec<_>) =
            device.pipeline.ingress.drain(..).partition(|pid| {
                device
                    .policies
                    .get(pid)
                    .is_some_and(|p| p.rules.iter().any(|r| r.to.is_some()))
            });
        device.pipeline.ingress = keep_ingress;
        if !to_egress.is_empty() {
            // Elles passaient avant les politiques de sortie existantes :
            // elles restent devant.
            let mut egress = to_egress;
            egress.append(&mut device.pipeline.egress);
            device.pipeline.egress = egress;
        }
    }
    network
}

#[cfg(test)]
mod tests {
    use super::*;
    use calque_model::{
        Action, Device, DeviceId, Network, Policy, PolicyId, Rule, RuleId, RuleMatch, SourceSpan,
        Vendor, ZoneId,
    };

    fn rule(to: Option<&str>) -> Rule {
        Rule {
            id: RuleId::new("1"),
            matches: RuleMatch::default(),
            from: None,
            to: to.map(ZoneId::new),
            action: Action::Accept,
            source: SourceSpan::new("test.conf", 1),
        }
    }

    fn network_with_policies(specs: &[(&str, Option<&str>)]) -> Network {
        let mut device = Device::new(DeviceId::new("fw"), Vendor::Fortigate);
        for (name, to) in specs {
            let pid = PolicyId::new(*name);
            device.policies.insert(
                pid.clone(),
                Policy {
                    id: pid.clone(),
                    rules: vec![rule(*to)],
                    default_action: Action::Deny,
                },
            );
            device.pipeline.ingress.push(pid);
        }
        let mut network = Network::default();
        network.devices.insert(device.id.clone(), device);
        network
    }

    #[test]
    fn deplace_les_politiques_contraignant_la_zone_de_sortie() {
        // `avec-to` contraint la zone de sortie, `sans-to` non : seule la
        // première passe au point de sortie, devant l'existant.
        let network = network_with_policies(&[("avec-to", Some("dmz")), ("sans-to", None)]);
        let prepared = prepare_for_engine(&network);
        let device = prepared.devices.values().next().expect("un équipement");
        assert_eq!(
            device.pipeline.ingress,
            vec![PolicyId::new("sans-to")],
            "la politique sans contrainte de sortie reste en entrée"
        );
        assert_eq!(
            device.pipeline.egress,
            vec![PolicyId::new("avec-to")],
            "la politique à couple de zones est évaluée en sortie"
        );
    }

    #[test]
    fn idempotente_et_sans_effet_sur_l_original() {
        let network = network_with_policies(&[("avec-to", Some("dmz")), ("sans-to", None)]);
        let once = prepare_for_engine(&network);
        let twice = prepare_for_engine(&once);
        assert_eq!(once, twice, "préparer deux fois ne change plus rien");
        // L'original n'est jamais modifié : la préparation copie.
        let device = network.devices.values().next().expect("un équipement");
        assert_eq!(device.pipeline.ingress.len(), 2);
        assert!(device.pipeline.egress.is_empty());
    }
}
