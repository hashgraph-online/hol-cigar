//! Exact composition of every typed production operation family.

use crate::{
    CatalogContextApplication, EffectServiceHandlers, OperationalHandlers,
    ProductionApplicationBuilder, ReplayServiceHandlers, SpaceHandoffApplication,
    register_catalog_context_handlers, register_effect_replay_handlers,
    register_operational_handlers, register_space_handoff_handlers,
};
use cigar_api::{CompleteServiceFacade, FacadeErrorFactory, HandlerRegistryError};
use cigar_store::{Repository, ServiceRepository};
use std::sync::Arc;

/// Complete handler families required by the frozen 45-operation production application.
pub struct ProductionHandlerFamilies<R>
where
    R: Repository + ServiceRepository,
{
    /// Seven daemon-owned operational handlers.
    pub operational: Arc<OperationalHandlers>,
    /// Six catalog and eight context handlers.
    pub catalog_context: Arc<CatalogContextApplication<R>>,
    /// Eight space and six handoff handlers.
    pub space_handoff: Arc<SpaceHandoffApplication>,
    /// Six effect handlers.
    pub effects: Arc<EffectServiceHandlers<R>>,
    /// Four replay handlers.
    pub replay: Arc<ReplayServiceHandlers>,
}

/// Registers and seals all 45 frozen operations through the marker-bound production builder.
///
/// Construction fails if any family is missing, duplicated, or registered under the wrong
/// operation kind. The returned facade is complete but deliberately not yet quota/idempotency
/// governed; [`crate::ProductionFacade`] remains the mandatory outer production boundary.
pub fn compose_complete_production_application<R>(
    errors: Arc<dyn FacadeErrorFactory>,
    families: ProductionHandlerFamilies<R>,
) -> Result<CompleteServiceFacade, HandlerRegistryError>
where
    R: Repository + ServiceRepository + 'static,
{
    let mut builder = ProductionApplicationBuilder::new(errors);
    register_operational_handlers(&mut builder, families.operational)?;
    register_catalog_context_handlers(&mut builder, families.catalog_context)?;
    register_space_handoff_handlers(&mut builder, families.space_handoff)?;
    register_effect_replay_handlers(&mut builder, families.effects, families.replay)?;
    builder.build()
}
