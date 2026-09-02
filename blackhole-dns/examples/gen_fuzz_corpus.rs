//! One-off helper to (re)generate `fuzz/corpus/dns_relay_parse/` seed
//! files from correctly wire-encoded DNS messages, so the fuzzer starts
//! from bytes that actually parse instead of only random noise. Hand-
//! encoding DNS wire format is error-prone; building it through
//! `hickory_proto::op::Message` guarantees byte-correctness.
//!
//! Run with `cargo run -p blackhole-dns --example gen_fuzz_corpus`
//! whenever the corpus needs regenerating.

use std::io::Write;
use std::path::{Path, PathBuf};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/corpus/dns_relay_parse")
}

fn write_corpus(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::create_dir_all(dir).expect("create corpus dir");
    let path = dir.join(name);
    std::fs::File::create(&path)
        .expect("create corpus file")
        .write_all(bytes)
        .expect("write corpus file");
    println!("wrote {}", path.display());
}

fn main() {
    let dir = corpus_dir();

    let mut msg = Message::new(1234, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(Name::from_ascii("example.com.").unwrap());
    q.set_query_type(RecordType::A);
    msg.add_query(q);
    write_corpus(&dir, "a_query", &msg.to_vec().unwrap());

    let mut msg = Message::new(5678, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(Name::from_ascii("example.org.").unwrap());
    q.set_query_type(RecordType::AAAA);
    msg.add_query(q);
    write_corpus(&dir, "aaaa_query", &msg.to_vec().unwrap());

    let mut msg = Message::new(1, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(Name::from_ascii("a.b.c.d.e.f.g.deeply.nested.example.net.").unwrap());
    q.set_query_type(RecordType::A);
    msg.add_query(q);
    write_corpus(&dir, "deep_subdomain_query", &msg.to_vec().unwrap());

    // No question section at all — exercises the `queries.first()?`
    // early-return path.
    let msg = Message::new(42, MessageType::Query, OpCode::Query);
    write_corpus(&dir, "no_question", &msg.to_vec().unwrap());

    // A record type our relay never answers (only A/AAAA are handled) —
    // exercises the "resolved IP doesn't match query type, drop it"
    // no-answer path in `Relay::build_response`.
    let mut msg = Message::new(99, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(Name::from_ascii("example.com.").unwrap());
    q.set_query_type(RecordType::MX);
    msg.add_query(q);
    write_corpus(&dir, "mx_query", &msg.to_vec().unwrap());
}
