//! Validation-preserving adapters from public operation results into the identity-only session.

use crate::workflow_context_session::{
    WorkflowAppliedDeltaRecord, WorkflowDeltaRecord, WorkflowEffectStatusRecord,
    WorkflowMaterializationRecord, WorkflowPlanRecord, WorkflowRevalidationRecord,
};
use cigar_api::{
    ContextDeltaResponse, ContextPlanResponse, EffectStatusResponse, MaterializationResponse,
    OperationPayload, RevalidationResponse,
};
use cigar_compiler::AppliedDelta;
use cigar_protocol::{ContentDigest, EffectState, RecordId, VersionId};

impl WorkflowPlanRecord for ContextPlanResponse {
    fn is_valid(&self) -> bool {
        self.validate_payload().is_ok()
    }

    fn plan_id(&self) -> &RecordId {
        &self.plan.plan_id
    }

    fn bundle_id(&self) -> &VersionId {
        &self.bundle_id
    }

    fn contract_digest(&self) -> &ContentDigest {
        &self.plan.contract_digest
    }
}

impl WorkflowDeltaRecord for ContextDeltaResponse {
    fn is_valid(&self) -> bool {
        self.validate_payload().is_ok()
    }

    fn base_bundle_id(&self) -> &VersionId {
        &self.delta.base_bundle_id
    }

    fn target_bundle_id(&self) -> &VersionId {
        &self.delta.target_bundle_id
    }

    fn delta_digest(&self) -> &ContentDigest {
        &self.delta_digest
    }
}

impl WorkflowAppliedDeltaRecord for AppliedDelta {
    fn base_bundle_id(&self) -> &VersionId {
        AppliedDelta::base_bundle_id(self)
    }

    fn target_bundle_id(&self) -> &VersionId {
        AppliedDelta::target_bundle_id(self)
    }

    fn delta_digest(&self) -> &ContentDigest {
        AppliedDelta::delta_digest(self)
    }
}

impl WorkflowMaterializationRecord for MaterializationResponse {
    fn is_valid(&self) -> bool {
        self.validate_payload().is_ok()
    }

    fn bundle_id(&self) -> &VersionId {
        &self.context.bundle_id
    }

    fn tokenizer_fingerprint(&self) -> &ContentDigest {
        &self.context.tokenizer_fingerprint
    }

    fn materializer_fingerprint(&self) -> &ContentDigest {
        &self.context.materializer_fingerprint
    }

    fn physical_input_tokens(&self) -> u32 {
        self.physical_input_tokens
    }
}

impl WorkflowEffectStatusRecord for EffectStatusResponse {
    fn is_valid(&self) -> bool {
        self.validate_payload().is_ok()
    }

    fn effect_id(&self) -> &RecordId {
        &self.effect_id
    }

    fn intent_digest(&self) -> &ContentDigest {
        &self.intent_digest
    }

    fn effect_version(&self) -> u64 {
        self.effect_version
    }

    fn state(&self) -> EffectState {
        self.state
    }

    fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    fn reconciliation_count(&self) -> u32 {
        self.reconciliation_count
    }
}

impl WorkflowRevalidationRecord for RevalidationResponse {
    fn is_valid(&self) -> bool {
        self.validate_payload().is_ok()
    }

    fn bundle_id(&self) -> &VersionId {
        &self.bundle_id
    }

    fn valid(&self) -> bool {
        self.valid
    }
}
