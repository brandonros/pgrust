//! Native previous-backup manifest input. JSON syntax/escaping stays in jsonapi.
use adt_json::jsonapi::{self, JsonError, JsonLex, JsonLexDe, JsonSem, JsonSemToken};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use types_error::{PgError, PgResult};

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRange {
    pub tli: u32,
    pub start: u64,
    pub end: u64,
}
#[derive(Debug)]
pub struct Uploaded {
    pub files: BTreeMap<Vec<u8>, u64>,
    pub ranges: Vec<WalRange>,
}
thread_local! {
    static UPLOADED: RefCell<Option<Rc<Uploaded>>> = const { RefCell::new(None) };
    static CLEANUP: Cell<bool> = const { Cell::new(false) };
}
pub fn current() -> Option<Rc<Uploaded>> {
    UPLOADED.with(|x| x.borrow().clone())
}
pub fn error(message: impl Into<String>) -> Box<PgError> {
    Box::new(PgError::error(message))
}

#[derive(Debug)]
enum Value {
    Text(Vec<u8>),
    Number(u64),
    Pending,
    Array,
}
type Fields = BTreeMap<Vec<u8>, Value>;
fn text<'a>(fields: &'a Fields, key: &[u8]) -> PgResult<&'a [u8]> {
    match fields.get(key) {
        Some(Value::Text(v)) => Ok(v),
        _ => Err(error("invalid manifest string field")),
    }
}
fn number(fields: &Fields, key: &[u8]) -> PgResult<u64> {
    match fields.get(key) {
        Some(Value::Number(v)) => Ok(*v),
        _ => Err(error("invalid manifest numeric field")),
    }
}
fn hex(input: &[u8]) -> PgResult<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err(error("invalid manifest hexadecimal value"));
    }
    input
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|_| error("invalid manifest hex"))?;
            u8::from_str_radix(s, 16).map_err(|_| error("invalid manifest hex"))
        })
        .collect()
}
fn lsn(input: &[u8]) -> PgResult<u64> {
    let s = std::str::from_utf8(input).map_err(|_| error("invalid manifest LSN"))?;
    let (hi, lo) = s
        .split_once('/')
        .ok_or_else(|| error("invalid manifest LSN"))?;
    Ok(
        (u32::from_str_radix(hi, 16).map_err(|_| error("invalid manifest LSN"))? as u64) << 32
            | u32::from_str_radix(lo, 16).map_err(|_| error("invalid manifest LSN"))? as u64,
    )
}
struct Parser {
    stack: Vec<(Fields, Vec<u8>)>,
    root: Option<Fields>,
    array: Option<Vec<u8>>,
    result: Uploaded,
}
impl Parser {
    fn file(&mut self, f: Fields) -> PgResult<()> {
        if f.keys().any(|k| {
            ![
                b"Path".as_slice(),
                b"Encoded-Path",
                b"Size",
                b"Last-Modified",
                b"Checksum-Algorithm",
                b"Checksum",
            ]
            .contains(&k.as_slice())
        }) {
            return Err(error("unrecognized manifest file field"));
        }
        let path = match (f.get(b"Path".as_slice()), f.get(b"Encoded-Path".as_slice())) {
            (Some(Value::Text(p)), None) => p.clone(),
            (None, Some(Value::Text(p))) => hex(p)?,
            _ => return Err(error("manifest file requires exactly one pathname")),
        };
        if path.is_empty()
            || path.contains(&0)
            || path.starts_with(b"/")
            || path
                .split(|b| *b == b'/')
                .any(|p| p == b".." || p.is_empty())
        {
            return Err(error("invalid manifest pathname"));
        }
        let size = number(&f, b"Size")?;
        if size > i64::MAX as u64 {
            return Err(error("invalid manifest file size"));
        }
        if f.contains_key(b"Last-Modified".as_slice()) {
            text(&f, b"Last-Modified")?;
        }
        if f.contains_key(b"Checksum".as_slice())
            || f.contains_key(b"Checksum-Algorithm".as_slice())
        {
            let len = match text(&f, b"Checksum-Algorithm")? {
                b"CRC32C" => 4,
                b"SHA224" => 28,
                b"SHA256" => 32,
                b"SHA384" => 48,
                b"SHA512" => 64,
                _ => return Err(error("invalid manifest checksum algorithm")),
            };
            if hex(text(&f, b"Checksum")?)?.len() != len {
                return Err(error("invalid manifest file checksum"));
            }
        }
        if self.result.files.insert(path, size).is_some() {
            return Err(error("duplicate manifest pathname"));
        }
        Ok(())
    }
    fn range(&mut self, f: Fields) -> PgResult<()> {
        if f.len() != 3 {
            return Err(error("invalid manifest WAL range fields"));
        }
        let tli = u32::try_from(number(&f, b"Timeline")?)
            .map_err(|_| error("invalid manifest timeline"))?;
        let start = lsn(text(&f, b"Start-LSN")?)?;
        let end = lsn(text(&f, b"End-LSN")?)?;
        if tli == 0 || start == 0 || start >= end || self.result.ranges.iter().any(|r| r.tli == tli)
        {
            return Err(error("invalid or duplicate manifest WAL range"));
        }
        self.result.ranges.push(WalRange { tli, start, end });
        Ok(())
    }
}
impl<'m> JsonSem<'m> for Parser {
    fn object_start(&mut self, _: &JsonLex<'_>) -> PgResult<bool> {
        if self.stack.len() > 1
            || (self.stack.len() == 1 && self.array.is_none())
            || self.root.is_some()
        {
            return Err(error("unexpected object in backup manifest"));
        }
        self.stack.push((Fields::new(), Vec::new()));
        Ok(true)
    }
    fn object_end(&mut self, _: &JsonLex<'_>) -> PgResult<bool> {
        let (f, _) = self
            .stack
            .pop()
            .ok_or_else(|| error("invalid manifest object"))?;
        if self.stack.is_empty() {
            self.root = Some(f);
        } else if self.array.as_deref() == Some(b"Files") {
            self.file(f)?;
        } else if self.array.as_deref() == Some(b"WAL-Ranges") {
            self.range(f)?;
        } else {
            return Err(error("unexpected manifest object"));
        }
        Ok(true)
    }
    fn object_field_start(&mut self, _: &JsonLex<'_>, name: &'m [u8], _: bool) -> PgResult<bool> {
        let (f, key) = self
            .stack
            .last_mut()
            .ok_or_else(|| error("invalid manifest field"))?;
        if f.insert(name.to_vec(), Value::Pending).is_some() {
            return Err(error("duplicate manifest field"));
        }
        *key = name.to_vec();
        Ok(true)
    }
    fn array_start(&mut self, _: &JsonLex<'_>) -> PgResult<bool> {
        if self.stack.len() != 1 || self.array.is_some() {
            return Err(error("unexpected manifest array"));
        }
        let (f, key) = &mut self.stack[0];
        if key != b"Files" && key != b"WAL-Ranges" {
            return Err(error("unexpected manifest array field"));
        }
        f.insert(key.clone(), Value::Array);
        self.array = Some(key.clone());
        Ok(true)
    }
    fn array_end(&mut self, _: &JsonLex<'_>) -> PgResult<bool> {
        self.array = None;
        Ok(true)
    }
    fn scalar(&mut self, _: &JsonLex<'_>, token: JsonSemToken<'m>) -> PgResult<bool> {
        if self.array.is_some() && self.stack.len() == 1 {
            return Err(error("manifest array requires objects"));
        }
        let value = match token {
            JsonSemToken::String(s) => Value::Text(s.to_vec()),
            JsonSemToken::Number(s) => Value::Number(
                std::str::from_utf8(s)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| error("invalid manifest unsigned integer"))?,
            ),
            _ => return Err(error("unexpected manifest scalar")),
        };
        let (f, key) = self
            .stack
            .last_mut()
            .ok_or_else(|| error("manifest must be an object"))?;
        f.insert(key.clone(), value);
        Ok(true)
    }
}

pub fn parse(input: &[u8], system: u64) -> PgResult<Uploaded> {
    if input.len() > MAX_MANIFEST_BYTES {
        return Err(error("backup manifest exceeds 64 MiB input limit"));
    }
    let cx = mcx::MemoryContext::new("parse previous backup manifest");
    let mut parser = Parser {
        stack: Vec::new(),
        root: None,
        array: None,
        result: Uploaded {
            files: BTreeMap::new(),
            ranges: Vec::new(),
        },
    };
    std::str::from_utf8(input).map_err(|_| error("backup manifest is not UTF-8"))?;
    let mut lex = JsonLexDe::new_utf8(cx.mcx(), input);
    if jsonapi::parse_sem(&mut lex, &mut parser)? != JsonError::Success {
        return Err(error("invalid JSON backup manifest"));
    }
    let f = parser
        .root
        .ok_or_else(|| error("manifest must be an object"))?;
    if f.len() != 5
        || number(&f, b"PostgreSQL-Backup-Manifest-Version")? != 2
        || number(&f, b"System-Identifier")? != system
        || !matches!(f.get(b"Files".as_slice()), Some(Value::Array))
        || !matches!(f.get(b"WAL-Ranges".as_slice()), Some(Value::Array))
        || parser.result.ranges.is_empty()
    {
        return Err(error(
            "invalid backup manifest version, system identifier or inventory",
        ));
    }
    // Native manifests put their self-checksum on the final line. It covers all
    // preceding bytes, including the preceding newline, not reserialized JSON.
    let end = input
        .len()
        .saturating_sub(usize::from(input.last() == Some(&b'\n')));
    let start = input[..end]
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|n| n + 1)
        .ok_or_else(|| error("manifest checksum line is missing"))?;
    if !input[start..]
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .collect::<Vec<_>>()
        .starts_with(b"\"Manifest-Checksum\"")
        || hex(text(&f, b"Manifest-Checksum")?)?.as_slice() != pg_sha2::sha256(&input[..start])
    {
        return Err(error("backup manifest checksum mismatch"));
    }
    Ok(parser.result)
}

pub fn upload() -> PgResult<()> {
    let cx = mcx::MemoryContext::new("UPLOAD_MANIFEST");
    let mut message = stringinfo::StringInfo::new_in(cx.mcx())?;
    let mut bytes = Vec::new();
    pqcomm::pq_putmessage(b'G', &[0, 0, 0])?;
    pqcomm::pq_flush()?;
    loop {
        // Keep cancellation from interrupting a framed message halfway through.
        struct CancelHoldoff;
        impl Drop for CancelHoldoff {
            fn drop(&mut self) {
                init_small::globals::ResumeCancelInterrupts();
            }
        }
        init_small::globals::HoldCancelInterrupts();
        let holdoff = CancelHoldoff;
        pqcomm::pq_startmsgread()?;
        let kind = pqcomm::pq_getbyte()?;
        if kind < 0 {
            return Err(error("EOF during manifest upload"));
        }
        let limit = match kind as u8 {
            b'd' => MAX_MANIFEST_BYTES as i32 + 4,
            b'c' | b'f' | b'H' | b'S' => 10000,
            _ => return Err(error("unexpected message during manifest upload")),
        };
        if pqcomm::pq_getmessage(&mut message, limit)? != 0 {
            return Err(error("EOF during manifest upload"));
        }
        drop(holdoff);
        postgres_seams::check_for_interrupts::call()?;
        match kind as u8 {
            b'd' => {
                let data = message.as_bytes();
                if data.len() > MAX_MANIFEST_BYTES - bytes.len() {
                    return Err(error("backup manifest exceeds 64 MiB input limit"));
                }
                bytes.extend_from_slice(data);
            }
            b'c' if message.as_bytes().is_empty() => break,
            b'H' | b'S' if message.as_bytes().is_empty() => (),
            b'f' => return Err(error("client aborted manifest upload")),
            _ => return Err(error("invalid manifest upload message")),
        }
    }
    let manifest = Rc::new(parse(&bytes, transam_xlog::GetSystemIdentifier())?);
    if !CLEANUP.replace(true) {
        mcx::register_session_cleanup(Box::new(|| {
            UPLOADED.with(|x| *x.borrow_mut() = None);
            CLEANUP.set(false);
        }));
    }
    UPLOADED.with(|x| *x.borrow_mut() = Some(manifest));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(files: &str, ranges: &str) -> Vec<u8> {
        let prefix = format!("{{\"PostgreSQL-Backup-Manifest-Version\":2,\"System-Identifier\":42,\n\"Files\":[{files}],\n\"WAL-Ranges\":[{ranges}],\n");
        let sum: String = pg_sha2::sha256(prefix.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{prefix}\"Manifest-Checksum\":\"{sum}\"}}\n").into_bytes()
    }
    const RANGE: &str = r#"{"Timeline":1,"Start-LSN":"0/100","End-LSN":"0/200"}"#;
    #[test]
    fn identity_checksum_and_encoded_path() {
        let bytes = manifest(r#"{"Encoded-Path":"626173652f352f31","Size":8192}"#, RANGE);
        let parsed = parse(&bytes, 42).unwrap();
        assert_eq!(parsed.files[b"base/5/1".as_slice()], 8192);
        assert_eq!(parsed.ranges[0].start, 256);
        assert!(parse(&bytes, 43).is_err());
        let mut broken = bytes.clone();
        let pos = broken.windows(4).position(|x| x == b"8192").unwrap();
        broken[pos] = b'7';
        assert!(parse(&broken, 42).is_err());
    }
    #[test]
    fn reject_invalid_inventory_and_shape() {
        for files in [
            r#"{"Path":"../1","Size":1}"#,
            r#"{"Path":"/base/1","Size":1}"#,
            r#"{"Path":"base/1","Encoded-Path":"61","Size":1}"#,
            r#"{"Path":"base/1","Size":-1}"#,
            r#"{"Path":"base/1","Size":1,"Size":2}"#,
            r#"{"Path":"base/1","Size":1},{"Path":"base/1","Size":1}"#,
            r#"{"Path":"base/1","Size":1,"Checksum":"00"}"#,
            r#"{"Path":"base/1","Size":1,"Checksum-Algorithm":"SHA256","Checksum":"00"}"#,
            r#"{"Path":"base/1","Size":{}}"#,
            "1",
            "[]",
            "null",
        ] {
            assert!(parse(&manifest(files, RANGE), 42).is_err(), "{files}");
        }
        assert!(parse(&manifest("", ""), 42).is_err());
        assert!(parse(&manifest("", &format!("{RANGE},{RANGE}")), 42).is_err());
        assert!(parse(&vec![b' '; MAX_MANIFEST_BYTES + 1], 42).is_err());
    }
    #[test]
    fn native_escaped_names_and_no_file_checksum() {
        let p = parse(
            &manifest(
                r#"{"Path":"base/\u00e9\"","Size":0,"Last-Modified":"2026-09-07 12:00:00 GMT"}"#,
                RANGE,
            ),
            42,
        )
        .unwrap();
        assert!(p.files.contains_key("base/é\"".as_bytes()));
    }
}
