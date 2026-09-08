//! Version-neutral input adapter for immutable CIGAR compiler comparisons.
use cigar_compiler::{CompileRequest,CompilerCandidate,CompilerProfile,DeterministicCompiler,
    FrozenInputs,RepresentationVariant,compiler_profile_digest};
use cigar_policy::PolicyOutcome;
use cigar_protocol::{Budget,Classification,ConsistencyMode,ContentDigest,ContextContract,ExtensionMap,
    InstructionAuthority,LaneKind,OperationClass,RecordId,SchemaVersion,SourceUri,TargetProfile,VersionId};
#[cfg(not(any(feature="legacy92",feature="legacy93")))]
use cigar_protocol::LineageId;
#[cfg(not(feature="legacy92"))]
use cigar_retrieval::RequirementRankingEvidence;
use cigar_retrieval::CandidateFeatures;
use serde::Deserialize;
use std::collections::{BTreeMap,BTreeSet};
use std::error::Error;
use std::io::{BufRead,Write};
use std::time::Instant;

#[derive(Deserialize)]
struct Document { id:String,tokens:u32,bits:u64, #[serde(default)] exact:u16 }
#[derive(Deserialize)]
struct Input { id:String,query:String,budget:u32,documents:Vec<Document>,edges:Vec<(String,String,String)>,
    #[serde(default)] profile:u8 }

fn digest(value:u64)->Result<ContentDigest,Box<dyn Error>> {
    Ok(ContentDigest::new(format!("1220{value:064x}"))?)
}
fn version(value:usize)->Result<VersionId,Box<dyn Error>> { Ok(VersionId::new(digest(value as u64+1)?.as_str())?) }

fn execute(input:Input)->Result<serde_json::Value,Box<dyn Error>> {
    let profile = match input.profile {
        #[cfg(not(any(feature="legacy92",feature="legacy93")))]
        4=>CompilerProfile::balanced_v4(),
        #[cfg(not(feature="legacy92"))]
        3=>CompilerProfile::balanced_v3(),
        _=>CompilerProfile::default(),
    };
    let ids = input.documents.iter().enumerate().map(|(i,d)|version(i).map(|v|(d.id.clone(),v)))
        .collect::<Result<BTreeMap<_,_>,_>>()?;
    let mut candidates=Vec::new();
    for (index,document) in input.documents.iter().enumerate() {
        let matched=document.bits!=0;
        let score=if matched {9000} else {0};
        let features=CandidateFeatures { requirement_match:score,exact_match:document.exact,lexical_match:score,
            semantic_match:0,graph_proximity:0,project_proximity:10000,task_proximity:0,
            authority:5000,verification:5000,freshness:10000,novelty:0,conflict_risk:0,staleness:0,
            estimated_tokens:document.tokens,requirement_coverage_bits:0,entity_coverage_bits:document.bits };
        let dependencies=input.edges.iter().filter(|(from,_,kind)|from==&document.id && kind=="requires")
            .filter_map(|(_,to,_)|ids.get(to).cloned()).collect();
        candidates.push(CompilerCandidate { version_id:version(index)?,logical_id:version(index)?,
            #[cfg(not(any(feature="legacy92",feature="legacy93")))]
            lineage_id:LineageId::new(format!("01890f47-8e7d-7b42-a1d2-{:012x}",index+1))?,
            canonical_uri:SourceUri::new(format!("file:///comparison/{index:08x}"))?,
            lane:LaneKind::Evidence,mandatory:false,requirement_indices:BTreeSet::new(),
            entity_coverage_bits:document.bits,features,policy_outcome:PolicyOutcome::Allow,
            pre_exclusion_reason:None,classification:Classification::Internal,
            instruction_authority:InstructionAuthority::Data,dependencies,
            representations:vec![RepresentationVariant::exact(digest(index as u64+10000)?,document.tokens)?],
            claim:None,provenance_digest:digest(index as u64+20000)? });
    }
    let contract=ContextContract { schema_version:SchemaVersion::new("cigar.context-contract",1)?,
        job_goal:input.query,operation_class:OperationClass::CodeChange,
        principal_id:RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f0001")?,purpose:"comparison".into(),
        context_space_id:None,project_ids:vec![RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f0002")?],
        target:TargetProfile {provider:"offline-comparison".into(),model_family:"o200k-base-counted-text".into(),
            tokenizer_fingerprint:digest(240)?,materializer_fingerprint:digest(241)?,max_context_tokens:input.budget+1000},
        budget:Budget {total_input_tokens:input.budget,output_reserve_tokens:1000,
            lane_input_tokens:BTreeMap::from([(LaneKind::Evidence,input.budget)])},
        requirements:vec![],consistency:ConsistencyMode::Strong,maximum_staleness:None,extensions:ExtensionMap::default() };
    #[cfg(not(feature="legacy92"))]
    let ranking_evidence=match input.profile {
        #[cfg(not(feature="legacy93"))]
        4=>Some(RequirementRankingEvidence::new_v4(digest(234)?,BTreeSet::new(),BTreeSet::new(),vec![])?),
        3=>Some(RequirementRankingEvidence::new(digest(234)?,BTreeSet::new(),BTreeSet::new(),vec![])?),
        _=>None,
    };
    let request=CompileRequest {contract, frozen:FrozenInputs {catalog_watermark:digest(230)?,graph_revision:digest(231)?,
        policy_digest:digest(232)?,index_fingerprints:BTreeSet::from([digest(233)?]),retrieval_plan_digest:digest(234)?,
        compiler_profile_digest:compiler_profile_digest(&profile)?,tokenizer_fingerprint:digest(240)?,materializer_fingerprint:digest(241)?},
        profile,candidates,
        #[cfg(not(feature="legacy92"))]
        ranking_evidence,
    };
    let started=Instant::now();
    match DeterministicCompiler.compile(request) {
        Ok(output)=>{
            let elapsed=started.elapsed().as_nanos();
            let chosen=output.bundle.blocks.iter().flat_map(|b|b.provenance.iter()).collect::<BTreeSet<_>>();
            let selected=ids.iter().filter(|(_,v)|chosen.contains(v)).map(|(id,_)|id).collect::<Vec<_>>();
            Ok(serde_json::json!({"case":input.id,"profile":input.profile,"selected":selected,
                "tokens":output.bundle.total_tokens,"latency_ns":elapsed,
                "bundle":output.bundle,"manifest":output.manifest,"plan":output.plan}))
        }
        Err(error)=>Ok(serde_json::json!({"case":input.id,"profile":input.profile,"error":format!("{:?}",error.code()),
            "latency_ns":started.elapsed().as_nanos(),"selected":[],"tokens":0})),
    }
}

fn main()->Result<(),Box<dyn Error>> {
    let stdin=std::io::stdin();
    let mut stdout=std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let input:Input=serde_json::from_str(&line?)?;
        writeln!(stdout,"{}",execute(input)?)?;
        stdout.flush()?;
    }
    Ok(())
}
