//! Runs the shared retry-policy vectors (`conformance/retry-policy-v1.json`, E13-T007) against
//! this client's `RetryPolicy`.

use std::time::Duration;

use interceptor_client::retry::{Action, Attempt, Connection, Event, RetryClass, RetryPolicy};
use serde_json::Value;

fn policy(config: &Value) -> RetryPolicy {
    let limit = |key: &str| config[key].as_u64().map(|n| u32::try_from(n).unwrap());
    RetryPolicy::new(
        Duration::from_millis(config["initial_retry_delay_ms"].as_u64().unwrap()),
        Duration::from_millis(config["max_retry_delay_ms"].as_u64().unwrap()),
        limit("max_retries_send"),
        limit("max_retries_other"),
    )
    .unwrap()
}

fn u32_at(value: &Value, key: &str) -> u32 {
    u32::try_from(value[key].as_u64().unwrap()).unwrap()
}

#[test]
fn every_retry_policy_vector_passes() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance/retry-policy-v1.json"),
    )
    .unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["version"], 1);
    let defaults = policy(&file["defaults"]);
    assert_eq!(defaults, RetryPolicy::default());

    let vectors = file["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let policy = vector.get("config").map_or(defaults, policy);
        let class = match vector["retry"].as_str().unwrap() {
            "idempotent" => RetryClass::Idempotent,
            "by-message-id" => RetryClass::ByMessageId,
            "once" => RetryClass::Once,
            other => panic!("{name}: retry {other}"),
        };
        let attempt = Attempt {
            retries: u32_at(&vector["attempt"], "retries"),
            redirects: u32_at(&vector["attempt"], "redirects"),
            jitter: u32_at(&vector["attempt"], "jitter"),
        };
        let event = &vector["event"];
        let code = event
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let endpoint = event.get("endpoint").and_then(Value::as_str);
        let event = match event["type"].as_str().unwrap() {
            "error" => Event::Error { code, endpoint },
            "connection_error" => Event::ConnectionError { code, endpoint },
            "close" => Event::Close { endpoint },
            "connection_lost" => Event::ConnectionLost {
                draining: event["draining"].as_bool().unwrap(),
                endpoint,
            },
            other => panic!("{name}: event {other}"),
        };

        let decision = policy.decide(class, attempt, event);
        let expect = &vector["expect"];
        let action = match decision.action {
            Action::Retry => "retry",
            Action::Surface => "surface",
            Action::Continue => "continue",
        };
        let (connection, to) = match decision.connection {
            Connection::Keep => ("keep", None),
            Connection::ConnectEndpoint(endpoint) => ("connect_endpoint", Some(endpoint)),
            Connection::ConnectService => ("connect_service", None),
            Connection::Close => ("close", None),
        };
        assert_eq!(action, expect["action"], "{name}");
        assert_eq!(
            decision.delay,
            Duration::from_millis(expect["delay_ms"].as_u64().unwrap()),
            "{name}"
        );
        assert_eq!(connection, expect["connection"], "{name}");
        assert_eq!(to, expect.get("endpoint").and_then(Value::as_str), "{name}");
    }
}

#[test]
fn settings_out_of_range_are_refused() {
    let ms = Duration::from_millis;
    assert!(RetryPolicy::new(ms(0), ms(10), None, None).is_err());
    assert!(RetryPolicy::new(ms(20), ms(10), None, None).is_err());
    assert!(RetryPolicy::new(ms(1), ms(1 << 31), None, None).is_err());
    assert!(RetryPolicy::new(ms(1), ms((1 << 31) - 1), None, None).is_ok());
}
