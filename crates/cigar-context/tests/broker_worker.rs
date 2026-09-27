//! Real worker subprocess and loopback tests. These do not replace independent SDK-process tests.
#![cfg(all(feature = "bpe", feature = "broker"))]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use cigar_context::broker::BrokerCredential;
use cigar_context::broker::authentication::{
    ClientHello, ClientProof, MAX_HANDSHAKE_FRAME, ServerProof,
};
use cigar_context::broker::protocol::{
    BROKER_PROTOCOL, MAX_AGENT_FRAME, MAX_AGENT_RESPONSE, read_frame, write_frame,
};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Worker {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<Vec<u8>>,
    next: u32,
    address: SocketAddr,
}

impl Worker {
    fn start(transport: Value) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cigar-context-worker"))
            .arg("--broker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let mut frame = Vec::new();
                if stdout
                    .by_ref()
                    .take(64 * 1024 * 1024 + 1)
                    .read_until(b'\n', &mut frame)
                    .unwrap_or(0)
                    == 0
                {
                    break;
                }
                if tx.send(frame).is_err() {
                    break;
                }
            }
        });
        let mut worker = Self {
            child,
            input,
            output: rx,
            next: 0,
            address: (Ipv4Addr::LOCALHOST, 1).into(),
        };
        let hello =
            worker.call(json!({"op":"init", "domain":"broker-test", "transport":transport}));
        let hello = success(&hello);
        assert_eq!(hello["host"], "127.0.0.1");
        assert_eq!(hello["requires_hol_services"], false);
        assert_eq!(hello["protocol"], BROKER_PROTOCOL);
        assert!(
            hello["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .all(|feature| !feature.as_str().unwrap().contains("durable"))
        );
        let port = u16::try_from(hello["port"].as_u64().unwrap()).unwrap();
        worker.address = (Ipv4Addr::LOCALHOST, port).into();
        worker
    }

    fn call(&mut self, command: Value) -> Value {
        self.next += 1;
        let mut frame = serde_json::to_vec(&json!({"id":self.next,"command":command})).unwrap();
        frame.push(b'\n');
        self.input.as_mut().unwrap().write_all(&frame).unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let frame = self.output.recv_timeout(Duration::from_secs(20)).unwrap();
        let reply: Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(reply["protocol"], BROKER_PROTOCOL);
        assert_eq!(reply["id"], self.next);
        reply
    }

    fn revision(&mut self, source: &str) -> Value {
        success(&self.call(json!({"op":"source_revision","source":source}))).clone()
    }

    fn ingest(&mut self, source: &str, id: &str, text: &str) {
        let expected = self.revision(source);
        let reply = self.call(
            json!({"op":"replace_source","source":source,"expected":expected,
            "documents":[{"id":id,"source":source,"text":text}],"provenance":provenance("host")}),
        );
        assert!(success(&reply)["revision"]["version"].is_string());
    }

    fn grant(&mut self, id: &str, allowed: &[&str], writable: &[&str]) -> Value {
        let reply = self.call(json!({"op":"grant","spec":{"view":{"id":id,"allowed_sources":allowed,
            "writable_sources":writable,"policy_revision":"host-1"},"limits":{},"lease_ms":60_000}}));
        success(&reply).clone()
    }

    fn wait_exit(&mut self) {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < until,
                "broker failed to close within its teardown bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn provenance(origin: &str) -> Value {
    json!({"authority":"fixture-host","upstream_revision":"fixture-1","observed_at_ms":1,
        "valid_until_ms":null,"origin":origin,"derived_from":[]})
}

fn success(reply: &Value) -> &Value {
    assert_eq!(
        reply["outcome"]["status"], "ok",
        "broker returned a failure status: {:?}",
        reply["outcome"]["error"]
    );
    &reply["outcome"]["result"]
}

fn envelope(command: Value) -> Value {
    json!({"protocol":BROKER_PROTOCOL,"id":1,"wait_ms":30_000,"command":command})
}

fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.set_nodelay(true).unwrap();
    stream
}

fn challenge(
    address: SocketAddr,
    credential: &Value,
) -> Result<(TcpStream, ClientHello, ServerProof), ()> {
    let credential: BrokerCredential =
        serde_json::from_value(credential.clone()).map_err(|_| ())?;
    let mut stream = connect(address);
    let hello = ClientHello::new(&credential).map_err(|_| ())?;
    write_frame(&mut stream, &hello, MAX_HANDSHAKE_FRAME).map_err(|_| ())?;
    let frame = read_frame(&mut stream, MAX_HANDSHAKE_FRAME).map_err(|_| ())?;
    let proof = serde_json::from_slice(&frame).map_err(|_| ())?;
    Ok((stream, hello, proof))
}

fn authenticate(address: SocketAddr, credential: &Value) -> Result<TcpStream, ()> {
    let (mut stream, hello, server) = challenge(address, credential)?;
    let credential = serde_json::from_value(credential.clone()).map_err(|_| ())?;
    let client = hello.verify_server(&credential, &server).map_err(|_| ())?;
    write_frame(&mut stream, &client, MAX_HANDSHAKE_FRAME).map_err(|_| ())?;
    Ok(stream)
}

fn agent(address: SocketAddr, credential: &Value, command: Value) -> Value {
    let mut stream = authenticate(address, credential).unwrap();
    write_frame(&mut stream, &envelope(command), MAX_AGENT_FRAME).unwrap();
    let frame = read_frame(&mut stream, MAX_AGENT_RESPONSE).unwrap();
    let reply: Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(reply["protocol"], BROKER_PROTOCOL);
    assert_eq!(reply["id"], 1);
    assert!(reply["timing"]["queue_us"].is_u64());
    assert!(reply["timing"]["service_us"].is_u64());
    reply
}

#[test]
fn twelve_concurrent_clients_share_one_owner_without_cross_scope_evidence() {
    let mut worker = Worker::start(json!({}));
    worker.ingest("shared", "common", "common public evidence");
    let mut credentials = Vec::new();
    for i in 0..12 {
        let source = format!("private-{i}");
        worker.ingest(
            &source,
            &format!("doc-{i}"),
            &format!("PRIVATE_AGENT_{i}_ evidence"),
        );
        credentials.push(worker.grant(&format!("agent-{i}"), &["shared", &source], &[&source]));
    }
    let mut clients = Vec::new();
    for (i, credential) in credentials.iter().enumerate() {
        let address = worker.address;
        let credential = credential.clone();
        clients.push(std::thread::spawn(move || agent(address, &credential,
            json!({"op":"compile","request":{"query":"evidence","required":["common",format!("doc-{i}")]}}))));
    }
    let contexts = clients
        .into_iter()
        .map(|client| success(&client.join().unwrap()).clone())
        .collect::<Vec<_>>();
    for (i, context) in contexts.iter().enumerate() {
        let text = context["rendered"].as_str().unwrap();
        assert!(text.contains("common public"));
        assert!(text.contains(&format!("PRIVATE_AGENT_{i}_")));
        assert_eq!(context["context"]["snapshot"]["stats"]["documents"], 2);
        for other in 0..12 {
            if other != i {
                assert!(!text.contains(&format!("PRIVATE_AGENT_{other}_")));
            }
        }
    }
    let cross_owner = agent(
        worker.address,
        &credentials[1],
        json!({"op":"revalidate","ticket":contexts[0]["ticket"]}),
    );
    assert_eq!(cross_owner["outcome"]["error"], "AccessDenied");
    worker.ingest("private-0", "doc-0", "PRIVATE_AGENT_0_ changed evidence");
    for i in 0..12 {
        let result = agent(
            worker.address,
            &credentials[i],
            json!({"op":"revalidate","ticket":contexts[i]["ticket"]}),
        );
        if i == 0 {
            assert_eq!(result["outcome"]["error"], "Stale");
        } else {
            success(&result);
        }
    }
    success(&worker.call(json!({"op":"close"})));
    worker.wait_exit();
}

#[test]
fn agent_proposals_need_host_admission_and_competing_cas_has_one_winner() {
    let mut worker = Worker::start(json!({}));
    let a = worker.grant("a", &["docs"], &["docs"]);
    let b = worker.grant("b", &["docs"], &["docs"]);
    let version = success(&agent(
        worker.address,
        &a,
        json!({"op":"source_revision","source":"docs"}),
    ))
    .clone();
    assert_eq!(version["version"], "0");
    let command = |id: &str| {
        json!({"op":"propose_source","request_key":id,"source":"docs","expected":version,
        "documents":[{"id":id,"source":"docs","text":format!("proposed evidence {id}")}]})
    };
    let pa = success(&agent(worker.address, &a, command("a-doc"))).clone();
    let pb = success(&agent(worker.address, &b, command("b-doc"))).clone();
    let before = agent(
        worker.address,
        &a,
        json!({"op":"compile","request":{"query":"evidence"}}),
    );
    assert!(
        success(&before)["context"]["snapshot"]["blocks"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let admitted = worker.call(json!({"op":"admit_proposal","proposal_id":pa["proposal_id"],"provenance":provenance("reviewed_proposal")}));
    assert_eq!(success(&admitted)["revision"]["version"], "1");
    let conflict = worker.call(json!({"op":"admit_proposal","proposal_id":pb["proposal_id"],"provenance":provenance("reviewed_proposal")}));
    assert_eq!(conflict["outcome"]["error"], "Conflict");
    let recovered = agent(
        worker.address,
        &a,
        json!({"op":"proposal_status","request_key":"a-doc"}),
    );
    assert_eq!(success(&recovered)["outcome"]["status"], "admitted");
    let after = agent(
        worker.address,
        &b,
        json!({"op":"compile","request":{"query":"evidence"}}),
    );
    assert!(
        success(&after)["rendered"]
            .as_str()
            .unwrap()
            .contains("a-doc")
    );
    assert!(
        !success(&after)["rendered"]
            .as_str()
            .unwrap()
            .contains("b-doc")
    );
}

#[test]
fn malformed_oversized_and_forged_connections_do_not_close_other_agents_graph() {
    let mut worker = Worker::start(json!({}));
    worker.ingest("docs", "one", "available evidence");
    let credential = worker.grant("reader", &["docs"], &[]);
    for command in [
        json!({"op":"grant"}),
        json!({"op":"check_answer"}),
        json!({"op":"replace_source","documents":[]}),
        json!({"op":"compile","request":{},"view":"root","PRIVATE_INPUT":true}),
    ] {
        let mut stream = authenticate(worker.address, &credential).unwrap();
        write_frame(&mut stream, &envelope(command), MAX_AGENT_FRAME).unwrap();
        assert!(read_frame(&mut stream, MAX_AGENT_RESPONSE).is_err());
    }
    let mut oversized = connect(worker.address);
    oversized.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert!(read_frame(&mut oversized, MAX_AGENT_RESPONSE).is_err());
    let mut oversized = authenticate(worker.address, &credential).unwrap();
    oversized.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert!(read_frame(&mut oversized, MAX_AGENT_RESPONSE).is_err());
    let mut wrong = credential.clone();
    wrong["secret"] = json!("0".repeat(64));
    assert!(authenticate(worker.address, &wrong).is_err());
    let valid = agent(
        worker.address,
        &credential,
        json!({"op":"compile","request":{"query":"evidence"}}),
    );
    assert!(
        success(&valid)["rendered"]
            .as_str()
            .unwrap()
            .contains("available evidence")
    );
    success(&worker.call(json!({"op":"revoke","agent":"reader"})));
    assert!(authenticate(worker.address, &credential).is_err());
}

#[test]
fn incomplete_prefix_times_out_and_releases_connection_capacity() {
    let mut worker = Worker::start(json!({"max_connections":1,"frame_timeout_ms":100}));
    let credential = worker.grant("reader", &[], &[]);
    let mut stalled = connect(worker.address);
    stalled.write_all(&[0]).unwrap();
    let mut byte = [0_u8; 1];
    let start = Instant::now();
    assert_eq!(stalled.read(&mut byte).unwrap(), 0);
    assert!(start.elapsed() < Duration::from_secs(3));
    let result = agent(
        worker.address,
        &credential,
        json!({"op":"compile","request":{"query":"evidence"}}),
    );
    success(&result);
}

#[test]
fn abandoned_agent_calls_leave_other_clients_and_host_control_available() {
    let mut worker = Worker::start(json!({}));
    worker.ingest("docs", "one", "shared evidence");
    let abandoned = worker.grant("abandoned", &["docs"], &[]);
    let healthy = worker.grant("healthy", &["docs"], &[]);
    for _ in 0..16 {
        let mut stream = authenticate(worker.address, &abandoned).unwrap();
        write_frame(
            &mut stream,
            &envelope(json!({"op":"compile","request":{"query":"evidence"}})),
            MAX_AGENT_FRAME,
        )
        .unwrap();
        drop(stream);
    }
    let response = agent(
        worker.address,
        &healthy,
        json!({"op":"compile","request":{"query":"evidence"}}),
    );
    success(&response);
    success(&worker.call(json!({"op":"revoke","agent":"abandoned"})));
    // Closing private stdin closes the owner and listener; there is no implicit orphan service.
    worker.input.take();
    worker.wait_exit();
}

#[test]
fn idle_owner_terminates_on_both_explicit_close_and_private_channel_eof() {
    for iteration in 0..8 {
        let mut worker = Worker::start(json!({}));
        if iteration % 2 == 0 {
            success(&worker.call(json!({"op":"close"})));
        } else {
            worker.input.take();
        }
        worker.wait_exit();
        assert!(TcpStream::connect_timeout(&worker.address, Duration::from_millis(100)).is_err());
    }
}

#[test]
fn replayed_reflected_and_revoked_mid_handshake_proofs_cannot_run_commands() {
    let mut worker = Worker::start(json!({}));
    let credential = worker.grant("reader", &["docs"], &[]);
    let native: BrokerCredential = serde_json::from_value(credential.clone()).unwrap();
    let (stream, hello, server) = challenge(worker.address, &credential).unwrap();
    let recorded = hello.verify_server(&native, &server).unwrap();
    drop(stream);
    for reflected in [false, true] {
        let (mut stream, _, fresh) = challenge(worker.address, &credential).unwrap();
        let proof = if reflected {
            ClientProof {
                protocol: BROKER_PROTOCOL.into(),
                proof: fresh.proof,
            }
        } else {
            recorded.clone()
        };
        write_frame(&mut stream, &proof, MAX_HANDSHAKE_FRAME).unwrap();
        assert!(read_frame(&mut stream, MAX_AGENT_RESPONSE).is_err());
    }
    let (mut stream, hello, server) = challenge(worker.address, &credential).unwrap();
    let client = hello.verify_server(&native, &server).unwrap();
    success(&worker.call(json!({"op":"revoke","agent":"reader"})));
    write_frame(&mut stream, &client, MAX_HANDSHAKE_FRAME).unwrap();
    assert!(read_frame(&mut stream, MAX_AGENT_RESPONSE).is_err());
    let renewed = worker.grant("reader", &["docs"], &[]);
    success(&agent(
        worker.address,
        &renewed,
        json!({"op":"source_revision","source":"docs"}),
    ));
}

#[test]
fn credentials_and_commands_are_not_accepted_as_handshake_shortcuts() {
    let mut worker = Worker::start(json!({}));
    let credential = worker.grant("reader", &["docs"], &[]);
    let command = envelope(json!({"op":"source_revision","source":"docs"}));
    let mut old = command.clone();
    old["credential"] = credential.clone();
    for request in [command, old.clone()] {
        let mut stream = connect(worker.address);
        write_frame(&mut stream, &request, MAX_AGENT_FRAME).unwrap();
        assert!(read_frame(&mut stream, MAX_AGENT_RESPONSE).is_err());
    }
    let mut stream = authenticate(worker.address, &credential).unwrap();
    write_frame(&mut stream, &old, MAX_AGENT_FRAME).unwrap();
    assert!(read_frame(&mut stream, MAX_AGENT_RESPONSE).is_err());
    success(&agent(
        worker.address,
        &credential,
        json!({"op":"source_revision","source":"docs"}),
    ));
}

#[test]
fn per_agent_connection_limit_preserves_another_grants_capacity() {
    let mut worker = Worker::start(
        json!({"max_connections":8,"max_connections_per_agent":2,"frame_timeout_ms":3000}),
    );
    let busy = worker.grant("busy", &["docs"], &[]);
    let healthy = worker.grant("healthy", &["docs"], &[]);
    let mut stalled = (0..3)
        .map(|_| {
            let mut stream = authenticate(worker.address, &busy).unwrap();
            stream.write_all(&[0]).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            stream
        })
        .collect::<Vec<_>>();
    let until = Instant::now() + Duration::from_secs(1);
    let mut rejected = false;
    while !rejected && Instant::now() < until {
        for stream in &mut stalled {
            match stream.read(&mut [0_u8; 1]) {
                Ok(0) => {
                    rejected = true;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                    rejected = true;
                    break;
                }
                Err(error) => assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                )),
                Ok(count) => assert_eq!(count, 0, "unexpected bytes before a command"),
            }
        }
    }
    assert!(
        rejected,
        "one grant exceeded its authenticated connection budget"
    );
    success(&agent(
        worker.address,
        &healthy,
        json!({"op":"source_revision","source":"docs"}),
    ));
    success(&worker.call(json!({"op":"revoke","agent":"busy"})));
}
