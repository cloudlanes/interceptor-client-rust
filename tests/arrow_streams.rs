//! Decodes the shared Arrow query-stream vector (`conformance/arrow-query-v1.bin`, E13-T005) and
//! a 1M-row query stream through `BatchStreamReader`, checking every value against
//! `interceptor-docs/client-api/arrow-streams.md` § Conformance rows.

use std::path::Path;
use std::sync::Arc;

use arrow_array::cast::AsArray as _;
use arrow_array::types::{Int8Type, Int64Type, TimestampNanosecondType};
use arrow_array::{
    Array as _, ArrayRef, BinaryArray, DictionaryArray, Int8Array, Int64Array, RecordBatch,
    StringArray, TimestampNanosecondArray,
};
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use bytes::Bytes;
use interceptor_client::arrow::{BatchStreamError, BatchStreamReader};
use serde_json::Value;

const EPOCH_NS: i64 = 1_767_225_600_000_000_000;
const STATES: [&str; 3] = ["active", "deferred", "scheduled"];
const MAX_FRAME: usize = 64 * 1024;

fn conformance(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("conformance")
            .join(name),
    )
    .unwrap()
}

fn manifest() -> Value {
    serde_json::from_slice(&conformance("arrow-query-v1.json")).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The vector's `DATA` payloads, the `OPEN` frame's kind byte removed.
fn vector_payloads(manifest: &Value) -> Vec<Bytes> {
    let bytes = Bytes::from(conformance("arrow-query-v1.bin"));
    assert_eq!(bytes.len() as u64, manifest["bytes"].as_u64().unwrap());
    let mut payloads = Vec::new();
    let mut at = 0;
    let mut fin = false;
    while at < bytes.len() {
        assert!(!fin, "a frame after FIN");
        let header = &bytes[at..at + 10];
        let stream_id = u32::from_be_bytes(header[..4].try_into().unwrap());
        let length = u32::from_be_bytes(header[6..].try_into().unwrap()) as usize;
        assert_eq!(
            u64::from(stream_id),
            manifest["stream_id"].as_u64().unwrap()
        );
        assert_eq!(header[4], 0x00, "DATA");
        let mut payload = bytes.slice(at + 10..at + 10 + length);
        if payloads.is_empty() {
            assert_eq!(header[5] & 0x01, 0x01, "OPEN");
            assert_eq!(
                u64::from(payload[0]),
                manifest["stream_kind"].as_u64().unwrap()
            );
            payload = payload.slice(1..);
        }
        fin = header[5] & 0x02 != 0;
        payloads.push(payload);
        at += 10 + length;
    }
    assert!(fin);
    assert_eq!(payloads.len() as u64, manifest["frames"].as_u64().unwrap());
    payloads
}

fn usize_of(i: usize) -> i64 {
    i64::try_from(i).unwrap()
}

/// The `body` of row `i`: `i mod 8` bytes, byte `j` being `(i + j) mod 256`.
fn body_of(i: usize) -> Vec<u8> {
    (0..i % 8)
        .map(|j| u8::try_from((i + j) % 256).unwrap())
        .collect()
}

/// Checks every value of `batch`, whose first row is row `first`.
fn check_rows(batch: &RecordBatch, first: usize) {
    let names: Vec<_> = batch
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect();
    assert_eq!(
        names,
        [
            "sequence_number",
            "enqueued_time_utc",
            "session_id",
            "state",
            "body"
        ]
    );
    let sequence = batch.column(0).as_primitive::<Int64Type>();
    let enqueued = batch.column(1).as_primitive::<TimestampNanosecondType>();
    let session = batch.column(2).as_string::<i32>();
    let state = batch.column(3).as_dictionary::<Int8Type>();
    let state_values = state.values().as_string::<i32>();
    let body = batch.column(4).as_binary::<i32>();
    assert_eq!(state_values.iter().flatten().collect::<Vec<_>>(), STATES);
    for row in 0..batch.num_rows() {
        let i = first + row;
        assert_eq!(sequence.value(row), usize_of(i));
        assert_eq!(enqueued.value(row), EPOCH_NS + usize_of(i) * 1_000_000);
        if i % 5 == 0 {
            assert!(session.is_null(row));
        } else {
            assert_eq!(session.value(row), format!("session-{}", i % 100));
        }
        assert_eq!(state.keys().value(row), i8::try_from(i % 3).unwrap());
        assert_eq!(body.value(row), body_of(i).as_slice());
    }
}

/// Pushes `payloads` and returns `(first row, rows)` of each batch, checking every value.
fn read_all(payloads: impl IntoIterator<Item = Bytes>) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut reader = BatchStreamReader::new();
    let mut pages = Vec::new();
    let mut rows = 0;
    for payload in payloads {
        reader.push(payload).unwrap();
        while let Some(batch) = reader.next_batch() {
            check_rows(&batch, rows);
            pages.push((rows, batch.num_rows()));
            rows += batch.num_rows();
        }
    }
    let header = reader.header().unwrap().to_vec();
    reader.finish().unwrap();
    (header, pages)
}

#[test]
fn the_conformance_vector_decodes_to_its_rows() {
    let manifest = manifest();
    let (header, pages) = read_all(vector_payloads(&manifest));
    assert_eq!(header, unhex(manifest["header"].as_str().unwrap()));
    let expected: Vec<(usize, usize)> = manifest["batches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let n = |key: &str| usize::try_from(b[key].as_u64().unwrap()).unwrap();
            (n("first_row"), n("rows"))
        })
        .collect();
    assert_eq!(pages, expected);
    let rows: usize = pages.iter().map(|(_, rows)| rows).sum();
    assert_eq!(rows as u64, manifest["rows"].as_u64().unwrap());
}

#[test]
fn payload_boundaries_do_not_matter() {
    let manifest = manifest();
    let stream: Vec<u8> = vector_payloads(&manifest).concat();
    let stream = Bytes::from(stream);
    let whole = read_all([stream.clone()]);
    for size in [1, 3, 8, 1000, 4096, MAX_FRAME + 5] {
        let chunks = (0..stream.len())
            .step_by(size)
            .map(|at| stream.slice(at..(at + size).min(stream.len())));
        assert_eq!(read_all(chunks), whole, "chunks of {size} bytes");
    }
}

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("sequence_number", DataType::Int64, false),
        Field::new(
            "enqueued_time_utc",
            DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        ),
        Field::new("session_id", DataType::Utf8, true),
        Field::new(
            "state",
            DataType::Dictionary(Box::new(DataType::Int8), Box::new(DataType::Utf8)),
            false,
        ),
        Field::new("body", DataType::Binary, false),
    ]))
}

/// Rows `first..first + rows` of § Conformance rows.
fn rows(schema: &SchemaRef, states: &ArrayRef, first: usize, rows: usize) -> RecordBatch {
    let range = first..first + rows;
    let keys = Int8Array::from_iter_values(range.clone().map(|i| i8::try_from(i % 3).unwrap()));
    let columns: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from_iter_values(range.clone().map(usize_of))),
        Arc::new(
            TimestampNanosecondArray::from_iter_values(
                range.clone().map(|i| EPOCH_NS + usize_of(i) * 1_000_000),
            )
            .with_timezone("UTC"),
        ),
        Arc::new(
            range
                .clone()
                .map(|i| (i % 5 != 0).then(|| format!("session-{}", i % 100)))
                .collect::<StringArray>(),
        ),
        Arc::new(DictionaryArray::<Int8Type>::try_new(keys, Arc::clone(states)).unwrap()),
        Arc::new(BinaryArray::from_iter_values(range.map(body_of))),
    ];
    RecordBatch::try_new(Arc::clone(schema), columns).unwrap()
}

#[test]
fn a_one_million_row_result_arrives_as_native_batches() {
    const ROWS: usize = 1_000_000;
    const PAGE: usize = 8192;
    let header = unhex(manifest()["header"].as_str().unwrap());
    let mut stream = u32::try_from(header.len()).unwrap().to_be_bytes().to_vec();
    stream.extend_from_slice(&header);
    let schema = schema();
    let states: ArrayRef = Arc::new(StringArray::from(STATES.to_vec()));
    let mut writer = StreamWriter::try_new(&mut stream, &schema).unwrap();
    for first in (0..ROWS).step_by(PAGE) {
        writer
            .write(&rows(&schema, &states, first, PAGE.min(ROWS - first)))
            .unwrap();
    }
    writer.finish().unwrap();
    drop(writer);

    let stream = Bytes::from(stream);
    let payloads = (0..stream.len())
        .step_by(MAX_FRAME)
        .map(|at| stream.slice(at..(at + MAX_FRAME).min(stream.len())));
    let (read_header, pages) = read_all(payloads);
    assert_eq!(read_header, header);
    assert_eq!(pages.len(), ROWS.div_ceil(PAGE));
    assert_eq!(pages.last(), Some(&(ROWS - ROWS % PAGE, ROWS % PAGE)));
    assert_eq!(pages.iter().map(|(_, rows)| rows).sum::<usize>(), ROWS);
}

/// The vector's stream bytes: the header, then the Arrow IPC stream.
fn vector_stream() -> Vec<u8> {
    vector_payloads(&manifest()).concat()
}

fn header_len() -> usize {
    4 + unhex(manifest()["header"].as_str().unwrap()).len()
}

#[test]
fn malformed_streams_are_refused() {
    let stream = vector_stream();
    let arrow = &stream[header_len()..];

    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        // (case, stream bytes, whether `push` fails rather than `finish`)
        ("no header", arrow.to_vec(), true),
        (
            "header over 1 MiB",
            [&0x0010_0001_u32.to_be_bytes()[..], arrow].concat(),
            true,
        ),
        ("ends inside the length prefix", stream[..3].to_vec(), false),
        (
            "ends inside the header",
            stream[..header_len() - 1].to_vec(),
            false,
        ),
        (
            "garbage after the header",
            [
                &stream[..header_len()],
                &[0xFF, 0xFF, 0xFF, 0xFF, 4, 0, 0, 0, 1, 2, 3, 4][..],
            ]
            .concat(),
            true,
        ),
        (
            "ends inside an Arrow message",
            stream[..stream.len() - 100].to_vec(),
            false,
        ),
        (
            "ends before the end-of-stream marker",
            stream[..stream.len() - 8].to_vec(),
            false,
        ),
        (
            "bytes after the end-of-stream marker",
            [&stream[..], &[0][..]].concat(),
            true,
        ),
    ];
    for (case, bytes, at_push) in cases {
        let mut reader = BatchStreamReader::new();
        let pushed = reader.push(Bytes::from(bytes));
        let error: BatchStreamError = if at_push {
            pushed.expect_err(case)
        } else {
            pushed.unwrap_or_else(|error| panic!("{case}: {error}"));
            while reader.next_batch().is_some() {}
            reader.finish().expect_err(case)
        };
        assert_eq!(error.code(), "protocol.malformed_frame", "{case}");
    }
}

#[test]
fn a_header_in_one_payload_is_not_copied() {
    let stream = Bytes::from(vector_stream());
    let mut reader = BatchStreamReader::new();
    reader.push(stream.clone()).unwrap();
    let header = reader.header().unwrap();
    assert_eq!(header.as_ptr(), stream[4..].as_ptr());
    assert!(reader.schema().is_some());
}
