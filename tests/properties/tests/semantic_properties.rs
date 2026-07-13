use cigar_canon::{
    CanonicalNode, DigestDomain, digest_v1, from_deterministic_cbor, parse_strict_json,
    to_deterministic_cbor, to_normalized_json,
};
use cigar_catalog::{ProjectIdentity, ProjectIdentityInput};
use cigar_compiler::ConservativeEstimator;
use cigar_crypto::MemoryKeyProvider;
use cigar_effects::{EffectCrashPoint, EffectFaultModel};
use cigar_policy::CapabilityAuthority;
use cigar_protocol::{
    Capability, CapabilityGrant, ExtensionMap, RecordId, SchemaVersion, UtcTimestamp, Validate,
};
use proptest::collection::{btree_map, btree_set, vec};
use proptest::prelude::*;

fn canonical_node() -> impl Strategy<Value = CanonicalNode> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(CanonicalNode::Boolean),
        any::<u32>().prop_map(|value| CanonicalNode::Unsigned(u64::from(value))),
        (-2_000_000_000_i64..0).prop_map(CanonicalNode::Negative),
        "[^\\p{C}]{0,64}".prop_map(CanonicalNode::Text),
    ];
    leaf.prop_recursive(5, 256, 16, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..16).prop_map(CanonicalNode::Array),
            btree_map("[a-zA-Z0-9_.-]{1,16}", inner, 0..16).prop_map(CanonicalNode::Map),
        ]
    })
}

fn record(number: u16) -> RecordId {
    RecordId::new(format!("01890f47-8e7d-7b42-a1d2-3c4d5e6f{number:04x}"))
        .expect("fixed record ID")
}

fn time(nanos: i128) -> UtcTimestamp {
    UtcTimestamp::from_unix_nanos(nanos).expect("fixed timestamp")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_iters: 16_384,
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct(
            "regressions/semantic-properties.txt",
        ))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn canonical_json_and_cbor_are_idempotent(node in canonical_node()) {
        let json = to_normalized_json(&node).expect("generated JSON node renders");
        let reparsed = parse_strict_json(&json).expect("normalized JSON parses");
        prop_assert_eq!(&reparsed, &node);
        let cbor = to_deterministic_cbor(&node).expect("generated node encodes");
        let decoded = from_deterministic_cbor(&cbor).expect("generated CBOR decodes");
        prop_assert_eq!(&decoded, &node);
        prop_assert_eq!(to_deterministic_cbor(&decoded).expect("re-encoding succeeds"), cbor);
    }

    #[test]
    fn any_canonical_payload_change_changes_the_domain_digest(
        node in canonical_node(),
        suffix in any::<u8>(),
    ) {
        let mut payload = to_deterministic_cbor(&node).expect("generated node encodes");
        let before = digest_v1(DigestDomain::Atom, &payload);
        payload.push(suffix);
        let after = digest_v1(DigestDomain::Atom, &payload);
        prop_assert_ne!(before, after);
        prop_assert_ne!(before, digest_v1(DigestDomain::Bundle, &payload[..payload.len() - 1]));
    }

    #[test]
    fn map_insertion_permutations_have_one_canonical_result(
        entries in btree_map("[a-z]{1,12}", any::<u32>(), 0..48),
    ) {
        let forward = CanonicalNode::Map(entries.iter().map(|(key, value)| {
            (key.clone(), CanonicalNode::Unsigned(u64::from(*value)))
        }).collect());
        let reverse = CanonicalNode::Map(entries.iter().rev().map(|(key, value)| {
            (key.clone(), CanonicalNode::Unsigned(u64::from(*value)))
        }).collect());
        prop_assert_eq!(
            to_deterministic_cbor(&forward).expect("forward map encodes"),
            to_deterministic_cbor(&reverse).expect("reverse map encodes"),
        );
    }

    #[test]
    fn project_identity_is_move_stable_and_fork_sensitive(
        remote in prop::option::of("(https|ssh|git)://[A-Za-z0-9.-]{1,24}/[A-Za-z0-9._/-]{1,40}"),
        disambiguator in "[A-Za-z0-9._-]{1,48}",
        fork_suffix in "[A-Za-z0-9]{1,12}",
    ) {
        let input = ProjectIdentityInput {
            tenant_id: record(1),
            git_remote: remote,
            root_lineage_id: record(2),
            disambiguator: disambiguator.clone(),
        };
        let first = ProjectIdentity::derive(input.clone()).expect("strategy emits valid identity");
        let moved = ProjectIdentity::derive(input.clone()).expect("same identity remains valid");
        prop_assert_eq!(&first, &moved);
        let fork = ProjectIdentity::derive(ProjectIdentityInput {
            disambiguator: format!("{disambiguator}-{fork_suffix}"),
            ..input
        }).expect("fork identity remains valid");
        prop_assert_ne!(first.project_id, fork.project_id);
    }

    #[test]
    fn conservative_budget_estimator_never_understates_its_own_bound(
        bytes in vec(any::<u8>(), 0..65_536),
        bytes_per_token in 1_u32..64,
        error_ppm in 0_u32..=1_000_000,
    ) {
        let estimate = ConservativeEstimator::new(bytes_per_token, error_ppm)
            .expect("strategy emits valid estimator")
            .estimate(&bytes)
            .expect("bounded input estimates");
        prop_assert!(estimate.upper_bound() >= estimate.estimated_tokens);
        prop_assert_eq!(
            estimate.upper_bound(),
            estimate.estimated_tokens.saturating_add(estimate.maximum_error_tokens),
        );
    }

    #[test]
    fn every_effect_fault_schedule_preserves_effect_safety(
        point_index in any::<usize>(),
        seed in any::<u64>(),
    ) {
        let point = EffectCrashPoint::ALL[point_index % EffectCrashPoint::ALL.len()];
        let snapshot = EffectFaultModel::inject(point, seed);
        let encoded = snapshot.to_json().expect("snapshot serializes");
        let decoded = cigar_effects::FaultSnapshot::from_json(&encoded).expect("snapshot decodes");
        prop_assert_eq!(decoded.point(), point);
        prop_assert_eq!(decoded.seed(), seed);
        prop_assert!(decoded.recover().verify().is_ok());
    }

    #[test]
    fn capability_attenuation_accepts_only_subsets(
        parent_indices in btree_set(0_usize..10, 1..=10),
        child_indices in btree_set(0_usize..10, 1..=10),
    ) {
        let capabilities = [
            Capability::ReadContext,
            Capability::CompileContext,
            Capability::WriteOverlay,
            Capability::PublishOverlay,
            Capability::CreateHandoff,
            Capability::AcceptHandoff,
            Capability::InvokeTool,
            Capability::ProposeEffect,
            Capability::ApproveEffect,
            Capability::ReconcileEffect,
        ];
        let parent_caps: Vec<_> = parent_indices.iter().map(|index| capabilities[*index]).collect();
        let child_caps: Vec<_> = child_indices.iter()
            .filter(|index| parent_indices.contains(index))
            .map(|index| capabilities[*index])
            .collect();
        prop_assume!(!child_caps.is_empty());
        let parent = CapabilityGrant {
            schema_version: SchemaVersion::new("cigar.capability-grant", 1).expect("schema"),
            grant_id: record(10),
            issuer_id: record(11),
            subject_id: record(12),
            parent_grant_id: None,
            capabilities: parent_caps,
            project_ids: vec![record(20), record(21)],
            processors: vec!["local".to_owned(), "remote".to_owned()],
            not_before: time(100),
            expires_at: time(1_000),
            delegation_depth: 3,
            extensions: ExtensionMap::default(),
        };
        prop_assume!(parent.validate().is_ok());
        let child = CapabilityGrant {
            schema_version: parent.schema_version.clone(),
            grant_id: record(13),
            issuer_id: parent.subject_id.clone(),
            subject_id: record(14),
            parent_grant_id: Some(parent.grant_id.clone()),
            capabilities: child_caps,
            project_ids: vec![record(20)],
            processors: vec!["local".to_owned()],
            not_before: time(200),
            expires_at: time(900),
            delegation_depth: 2,
            extensions: ExtensionMap::default(),
        };
        prop_assume!(child.validate().is_ok());
        let authority = CapabilityAuthority::new(std::sync::Arc::new(MemoryKeyProvider::default()));
        prop_assert!(authority.validate_attenuation(&child, &parent).is_ok());

        let mut broadened = child;
        if let Some(extra) = capabilities.iter().find(|capability| !parent.capabilities.contains(capability)) {
            broadened.capabilities.push(*extra);
            broadened.capabilities.sort();
            prop_assert!(authority.validate_attenuation(&broadened, &parent).is_err());
        }
    }
}
