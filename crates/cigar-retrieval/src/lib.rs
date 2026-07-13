//! Exact, lexical, temporal, graph, and optional vector candidate generation.

mod contract;
mod executor;
mod index;
mod planner;
mod vector;
mod worker;

pub use contract::*;
pub use executor::{ExecutedStage, StagedRetrieval, StagedRetrievalResult};
pub use index::{InMemoryIndexManager, IndexBuild, IndexGenerationDescriptor};
pub use planner::{PlannedStage, QueryPlan, QueryPlanner, QueryPlannerProfile};
pub use vector::{VectorAdapter, VectorNeighbor, VectorQuery};
pub use worker::{IndexSnapshot, IndexSnapshotProvider, IndexWorker, IndexWorkerReceipt};
