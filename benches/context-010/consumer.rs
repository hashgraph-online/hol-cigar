//! Standalone packaged-crate consumer; built outside the CIGAR workspace.
use cigar_context::{ContextGraph,ContextRequest,Document,EdgeKind,GraphLimits,Utf8ByteCounter};
use std::error::Error;

fn main() -> Result<(),Box<dyn Error>> {
    let mut graph=ContextGraph::new("consumer",GraphLimits::default())?;
    graph.upsert(Document::new("retry","src/retry","retry identity"))?;
    graph.upsert(Document::new("contract","docs/api","MUST retain the original operation"))?;
    graph.link("retry","contract",EdgeKind::Requires)?;
    let query=ContextRequest {query:"retry".into(),..ContextRequest::default()};
    let snapshot=graph.compile(&query,&Utf8ByteCounter)?;
    snapshot.verify(&Utf8ByteCounter)?;
    assert!(snapshot.render().contains("MUST retain"));
    let delta=snapshot.delta_from(&snapshot,&Utf8ByteCounter)?;
    assert_eq!(delta.apply(&snapshot,&Utf8ByteCounter)?,snapshot);
    let update=graph.replace_source("src/retry",vec![Document::new("retry","src/retry","retry UPDATED identity")])?;
    assert_eq!(update.replaced,1);
    let updated=graph.compile(&query,&Utf8ByteCounter)?;
    assert!(updated.render().contains("UPDATED"));
    assert!(updated.render().contains("MUST retain"));
    #[cfg(feature="bpe")]
    {
        let tokenizer=cigar_context::O200kTokenizer::new()?;
        let snapshot=graph.compile(&query,&tokenizer)?;
        snapshot.verify(&tokenizer)?;
        assert!(snapshot.stats().rendered_tokens<query.max_tokens);
        assert!(tokenizer.cache_stats()?.hits>0);
        tokenizer.clear_cache()?;
        assert_eq!(tokenizer.cache_stats()?.entries,0);
    }
    println!("packaged consumer passed");
    Ok(())
}
