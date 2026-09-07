use crate::{Result, digest};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::io::Read;
use std::time::Duration;

const MAX_BODY: usize = 64 * 1024 * 1024;

// Keep transport failures distinguishable from ownership, permission and
// integrity errors without retaining HTTP errors containing signed URLs.
#[derive(Debug, PartialEq, Eq)]
enum RequestFailure {
    Transient,
    Refused,
}
impl std::fmt::Display for RequestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Transient => "S3 request temporarily failed or its result is unknown",
            Self::Refused => "S3 request was refused",
        })
    }
}
impl std::error::Error for RequestFailure {}

fn retry_snapshot<T>(
    mut operation: impl FnMut() -> Result<T>,
    mut pause: impl FnMut(i64) -> Result<()>,
    mut now: impl FnMut() -> i64,
) -> Result<T> {
    let started = now();
    let mut delay = 250;
    loop {
        match operation() {
            Err(error)
                if error.downcast_ref::<RequestFailure>() == Some(&RequestFailure::Transient) =>
            {
                let remaining = 60_000 - (now() - started);
                if remaining <= 0 {
                    return Err(error);
                }
                pause(delay.min(remaining))?;
                if now() - started >= 60_000 {
                    return Err(error);
                }
                delay = (delay * 2).min(4_000);
            }
            result => return result,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct Object {
    pub body: Vec<u8>,
    pub etag: String,
}
#[derive(Clone)]
pub struct Store {
    bucket: Bucket,
    credentials: Credentials,
    agent: ureq::Agent,
    prefix: String,
    snapshot_retries: bool,
}
impl Store {
    pub fn new(endpoint: &str, bucket: String, region: String, prefix: String) -> Result<Self> {
        let endpoint: url::Url = endpoint.parse().map_err(|_| "invalid S3 endpoint")?;
        if endpoint.scheme() != "https"
            && !(endpoint.scheme() == "http"
                && matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost")))
        {
            return Err("nonlocal S3 endpoints require HTTPS".into());
        }
        if prefix.is_empty()
            || !prefix.ends_with('/')
            || prefix.starts_with('/')
            || prefix.split('/').any(|p| p == "..")
        {
            return Err("S3 prefix must be nonempty, relative and end in /".into());
        }
        let key =
            std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| "AWS_ACCESS_KEY_ID is required")?;
        let secret = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| "AWS_SECRET_ACCESS_KEY is required")?;
        let credentials = match std::env::var("AWS_SESSION_TOKEN") {
            Ok(token) => Credentials::new_with_token(key, secret, token),
            Err(_) => Credentials::new(key, secret),
        };
        let deadline = Duration::from_secs(5);
        Ok(Self {
            bucket: Bucket::new(endpoint, UrlStyle::Path, bucket, region)
                .map_err(|_| "invalid S3 bucket configuration")?,
            credentials,
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(deadline)
                .timeout_read(deadline)
                .timeout_write(deadline)
                .timeout(deadline)
                .build(),
            prefix,
            snapshot_retries: false,
        })
    }
    pub fn retry_snapshot_uploads(mut self) -> Self {
        self.snapshot_retries = true;
        self
    }
    fn request(
        &self,
        key: &str,
        body: Option<&[u8]>,
        expected: Option<&str>,
    ) -> Result<Option<Object>> {
        let key = format!("{}{key}", self.prefix);
        let response = if let Some(body) = body {
            if body.len() > MAX_BODY {
                return Err("S3 object exceeds 64 MiB".into());
            }
            let mut action = self.bucket.put_object(Some(&self.credentials), &key);
            let (name, value) = expected.map_or(("if-none-match", "*"), |v| ("if-match", v));
            action.headers_mut().insert(name, value);
            self.agent
                .put(action.sign(Duration::from_secs(300)).as_str())
                .set(name, value)
                .send_bytes(body)
        } else {
            self.agent
                .get(
                    self.bucket
                        .get_object(Some(&self.credentials), &key)
                        .sign(Duration::from_secs(300))
                        .as_str(),
                )
                .call()
        };
        let response = match response {
            Ok(r) => r,
            Err(ureq::Error::Status(404, r)) if body.is_none() => {
                let mut bytes = Vec::new();
                r.into_reader()
                    .take(65537)
                    .read_to_end(&mut bytes)
                    .map_err(|_| RequestFailure::Transient)?;
                if bytes.len() <= 65536
                    && String::from_utf8_lossy(&bytes).contains("<Code>NoSuchKey</Code>")
                {
                    return Ok(None);
                }
                return Err("S3 bucket missing or inaccessible".into());
            }
            Err(ureq::Error::Transport(_))
            | Err(ureq::Error::Status(408 | 409 | 429 | 500..=599, _)) => {
                return Err(RequestFailure::Transient.into());
            }
            Err(ureq::Error::Status(412, _)) => return Err("S3 precondition failed".into()),
            // Do not expose HTTP errors: signed URLs carry credentials.
            Err(_) => return Err(RequestFailure::Refused.into()),
        };
        if response.status() != 200 {
            return Err("unexpected S3 status".into());
        }
        let etag = response
            .header("etag")
            .ok_or("S3 response lacks ETag")?
            .to_owned();
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RequestFailure::Transient)?;
        if bytes.len() > MAX_BODY {
            return Err("oversized S3 response".into());
        }
        Ok(Some(Object {
            body: body.map_or(bytes, |b| b.to_vec()),
            etag,
        }))
    }
    pub fn get(&self, key: &str) -> Result<Option<Object>> {
        for _ in 0..2 {
            if let Ok(o) = self.request(key, None, None) {
                return Ok(o);
            }
        }
        self.request(key, None, None)
    }
    pub fn required(&self, key: &str) -> Result<Object> {
        self.get(key)?
            .ok_or_else(|| "required S3 object is missing".into())
    }
    pub fn conditional(&self, key: &str, body: &[u8], prior: Option<&Object>) -> Result<Object> {
        let mut last_error = None;
        for _ in 0..3 {
            match self.request(key, Some(body), prior.map(|o| o.etag.as_str())) {
                Ok(Some(o)) => return Ok(o),
                Ok(None) => return Err("S3 PUT returned no object".into()),
                Err(error)
                    if error.downcast_ref::<RequestFailure>() == Some(&RequestFailure::Refused) =>
                {
                    return Err(error);
                }
                Err(error) => last_error = Some(error),
            }
            let current = self.get(key)?;
            if let Some(o) = &current {
                if o.body == body {
                    return Ok(o.clone());
                }
            }
            if current.as_ref() != prior {
                return Err("S3 ownership conflict; refusing to rebase publication".into());
            }
        }
        Err(last_error.expect("publication attempted three times"))
    }
    pub fn immutable(&self, kind: &str, body: &[u8]) -> Result<String> {
        let key = digest(body);
        let name = format!("{kind}/{key}");
        if self.snapshot_retries {
            let mut warned = false;
            // Retry the identical object, not the export: its capture, salt and
            // content address survive an outage, so retries create no new names.
            retry_snapshot(
                || {
                    postgres_seams::check_for_interrupts::call()?;
                    self.conditional(&name, body, None)
                },
                |ms| {
                    if !warned {
                        elog::elog(
                            types_error::WARNING,
                            "retrying transient S3 snapshot upload failure",
                        )?;
                        warned = true;
                    }
                    latch::ResetLatch(
                        init_small::globals::MyLatch().ok_or("snapshot worker has no latch")?,
                    );
                    postgres_seams::check_for_interrupts::call()?;
                    crate::wait(ms)?;
                    postgres_seams::check_for_interrupts::call()?;
                    Ok(())
                },
                pg_clock::mono_ms,
            )?;
        } else {
            self.conditional(&name, body, None)?;
        }
        Ok(key)
    }
    pub fn delete(&self, key: &str) -> Result<()> {
        if !owned_key(key) {
            return Err("unsupported retirement key".into());
        }
        let key = format!("{}{key}", self.prefix);
        for _ in 0..3 {
            let url = self
                .bucket
                .delete_object(Some(&self.credentials), &key)
                .sign(Duration::from_secs(300));
            if let Ok(response) = self.agent.delete(url.as_str()).call() {
                if response.status() == 204 {
                    return Ok(());
                }
            }
        }
        Err("S3 retirement failed or its result is unknown".into())
    }
    /// Ordered pages permit deletion between requests without retaining a
    /// bucket-sized inventory or relying on an opaque continuation cursor.
    pub fn list_after(&self, after: Option<&str>) -> Result<Vec<String>> {
        for _ in 0..3 {
            if let Ok(keys) = self.list_page(after) {
                return Ok(keys);
            }
        }
        Err("S3 archive listing failed".into())
    }
    fn list_page(&self, after: Option<&str>) -> Result<Vec<String>> {
        let mut action = self.bucket.list_objects_v2(Some(&self.credentials));
        action.with_prefix(self.prefix.as_str());
        action.with_max_keys(1000);
        if let Some(after) = after {
            action.with_start_after(format!("{}{after}", self.prefix));
        }
        let response = self
            .agent
            .get(action.sign(Duration::from_secs(300)).as_str())
            .call()
            .map_err(|_| "S3 archive listing failed")?;
        if response.status() != 200 {
            return Err("unexpected S3 listing status".into());
        }
        let mut body = Vec::new();
        response
            .into_reader()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut body)
            .map_err(|_| "S3 listing response interrupted")?;
        if body.len() > 4 * 1024 * 1024 {
            return Err("S3 listing response limit".into());
        }
        let page = rusty_s3::actions::ListObjectsV2::parse_response(
            std::str::from_utf8(&body).map_err(|_| "non UTF-8 S3 listing")?,
        )
        .map_err(|_| "invalid S3 listing response")?;
        if page.contents.len() > 1000
            || (page.contents.is_empty() && page.next_continuation_token.is_some())
        {
            return Err("invalid S3 listing page".into());
        }
        let mut keys = Vec::new();
        let mut previous = after.unwrap_or("").to_string();
        for entry in page.contents {
            let key = entry
                .key
                .strip_prefix(&self.prefix)
                .ok_or("S3 listing escaped archive prefix")?;
            if key.is_empty() || key <= previous.as_str() {
                return Err("unordered S3 listing".into());
            }
            previous = key.to_string();
            keys.push(previous.clone());
        }
        Ok(keys)
    }
    pub fn verified(&self, kind: &str, key: &str) -> Result<Vec<u8>> {
        if !address(key) {
            return Err("invalid content address".into());
        }
        let body = self.required(&format!("{kind}/{key}"))?.body;
        if digest(&body) != key {
            return Err("corrupt content-addressed object".into());
        }
        Ok(body)
    }
}
pub fn owned_key(key: &str) -> bool {
    key.split_once('/').is_some_and(|(kind, key)| {
        [
            "chunks",
            "descriptors",
            "backups",
            "backup-chunks",
            "snapshot-index",
            "retired",
            "histories",
        ]
        .contains(&kind)
            && address(key)
    })
}
pub fn address(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    // A local protocol fixture; no credentials or real bucket are used here.
    fn fixture(
        replies: Vec<Option<(u16, &'static str, &'static str)>>,
    ) -> (Store, std::thread::JoinHandle<Vec<(String, Vec<u8>)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut length = 0;
                let mut headers = line;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = n.trim().parse().unwrap();
                    }
                    headers.push_str(&line);
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                requests.push((headers, body));
                if let Some((status, etag, body)) = reply {
                    write!(stream,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nETag: {etag}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                }
            }
            requests
        });
        let store = Store {
            bucket: Bucket::new(
                format!("http://{addr}").parse().unwrap(),
                UrlStyle::Path,
                "test",
                "us-east-1",
            )
            .unwrap(),
            credentials: Credentials::new("test", "test"),
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(2))
                .build(),
            prefix: "test/".into(),
            snapshot_retries: false,
        };
        (store, thread)
    }
    #[test]
    fn listing_decodes_keys_and_keeps_pagination_inside_prefix() {
        let key = format!("chunks/{}", "a".repeat(64));
        let xml = format!(
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><EncodingType>url</EncodingType><Contents><Key>test%2Fchunks%2F{}</Key><ETag>e</ETag><LastModified>2026-09-07T00:00:00Z</LastModified><Size>1</Size></Contents></ListBucketResult>",
            "a".repeat(64)
        );
        let (s, t) = fixture(vec![
            Some((200, "unused", Box::leak(xml.into_boxed_str()))),
            Some((
                200,
                "unused",
                "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
            )),
        ]);
        assert_eq!(s.list_after(None).unwrap(), vec![key.clone()]);
        assert!(s.list_after(Some(&key)).unwrap().is_empty());
        let requests = t.join().unwrap();
        assert!(requests[0].0.contains("prefix=test%2F"));
        assert!(requests[1].0.contains("start-after=test%2Fchunks%2F"));
        assert!(!owned_key(
            "neighbor/chunks/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!owned_key("notes.txt"));
    }

    #[test]
    fn listing_refuses_keys_outside_archive_prefix() {
        let xml = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Contents><Key>other/chunks/key</Key><ETag>e</ETag><LastModified>2026-09-07T00:00:00Z</LastModified><Size>1</Size></Contents></ListBucketResult>";
        let (s, t) = fixture(vec![Some((200, "unused", xml)); 3]);
        assert!(s.list_after(None).is_err());
        assert!(t.join().unwrap().iter().all(|(h, _)| h.starts_with("GET ")));
    }

    #[test]
    fn lost_delete_response_can_be_retried_without_republishing() {
        let (s, t) = fixture(vec![None, Some((204, "unused", ""))]);
        s.delete(&format!("chunks/{}", "0".repeat(64))).unwrap();
        let calls = t.join().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|(h, b)| h.starts_with("DELETE ") && b.is_empty())
        );
        assert!(s.delete("head").is_err());
        assert!(s.delete("chunks/../head").is_err());
    }

    #[test]
    fn lost_put_response_is_confirmed_by_exact_body() {
        let (s, t) = fixture(vec![None, Some((200, "new", "proposed"))]);
        let prior = Object {
            body: b"old".to_vec(),
            etag: "old-tag".into(),
        };
        assert_eq!(
            s.conditional("head", b"proposed", Some(&prior))
                .unwrap()
                .body,
            b"proposed"
        );
        let calls = t.join().unwrap();
        assert!(calls[0].0.to_lowercase().contains("if-match: old-tag"));
        assert!(calls[1].0.starts_with("GET "));
    }
    #[test]
    fn conflict_never_rebases_to_winners_etag() {
        let (s, t) = fixture(vec![
            Some((412, "none", "")),
            Some((200, "winner-tag", "winner")),
        ]);
        let prior = Object {
            body: b"old".to_vec(),
            etag: "old-tag".into(),
        };
        assert!(s.conditional("head", b"proposed", Some(&prior)).is_err());
        assert_eq!(t.join().unwrap().len(), 2);
    }
    #[test]
    fn retry_preserves_original_condition_and_body() {
        let (s, t) = fixture(vec![
            None,
            Some((200, "old-tag", "old")),
            Some((200, "new-tag", "")),
        ]);
        let prior = Object {
            body: b"old".to_vec(),
            etag: "old-tag".into(),
        };
        assert_eq!(
            s.conditional("head", b"proposed", Some(&prior))
                .unwrap()
                .etag,
            "new-tag"
        );
        let calls = t.join().unwrap();
        assert_eq!(calls[0].1, calls[2].1);
        assert!(calls[0].0.to_lowercase().contains("if-match: old-tag"));
        assert!(calls[2].0.to_lowercase().contains("if-match: old-tag"));
    }
    #[test]
    fn snapshot_retry_reuses_object_after_throttling_and_lost_response() {
        let absent = Some((404, "unused", "<Code>NoSuchKey</Code>"));
        let mut replies = Vec::new();
        for status in [503, 429, 503, 409] {
            replies.extend([Some((status, "unused", "")), absent]);
        }
        replies.extend([None, Some((200, "landed", "payload"))]);
        let (s, t) = fixture(replies);
        let clock = std::cell::Cell::new(0);
        let result = retry_snapshot(
            || s.conditional("backup-chunks/fixed", b"payload", None),
            |ms| {
                clock.set(clock.get() + ms);
                Ok(())
            },
            || clock.get(),
        )
        .unwrap();
        assert_eq!(result.body, b"payload");
        assert!(clock.get() > 0);
        let requests = t.join().unwrap();
        let puts = requests
            .iter()
            .filter(|(h, _)| h.starts_with("PUT "))
            .collect::<Vec<_>>();
        assert_eq!(puts.len(), 5);
        for (headers, body) in puts {
            assert!(headers.starts_with("PUT /test/test/backup-chunks/fixed?"));
            assert!(headers.to_lowercase().contains("if-none-match: *"));
            assert_eq!(body, b"payload");
        }
    }
    #[test]
    fn snapshot_retry_is_bounded_and_interruptible() {
        let clock = std::cell::Cell::new(0);
        let attempts = std::cell::Cell::new(0);
        let result: Result<()> = retry_snapshot(
            || {
                attempts.set(attempts.get() + 1);
                Err(RequestFailure::Transient.into())
            },
            |ms| {
                assert!((1..=4000).contains(&ms));
                clock.set(clock.get() + ms);
                Ok(())
            },
            || clock.get(),
        );
        assert_eq!(
            result.unwrap_err().downcast_ref::<RequestFailure>(),
            Some(&RequestFailure::Transient)
        );
        assert_eq!(clock.get(), 60_000);
        assert!(attempts.get() > 3 && attempts.get() < 30);
        let mut attempts = 0;
        let result: Result<()> = retry_snapshot(
            || {
                attempts += 1;
                Err(RequestFailure::Transient.into())
            },
            |_| Err("shutdown requested".into()),
            || 0,
        );
        assert_eq!(result.unwrap_err().to_string(), "shutdown requested");
        assert_eq!(attempts, 1);
    }
    #[test]
    fn permission_errors_do_not_get_snapshot_grace_period() {
        let (s, t) = fixture(vec![Some((403, "unused", ""))]);
        let result = retry_snapshot(
            || s.conditional("backup-chunks/fixed", b"payload", None),
            |_| panic!("permission failure must not get extended retries"),
            || 0,
        );
        assert!(result.is_err());
        assert_eq!(t.join().unwrap().len(), 1);
    }
    #[test]
    fn snapshot_policy_does_not_extend_head_publication() {
        let (mut s, t) =
            fixture([Some((503, "unused", "")), Some((200, "old", "prior"))].repeat(3));
        s.snapshot_retries = true;
        assert!(
            s.conditional(
                "head",
                b"new",
                Some(&Object {
                    body: b"prior".to_vec(),
                    etag: "old".into()
                })
            )
            .is_err()
        );
        assert_eq!(t.join().unwrap().len(), 6);
    }
}
