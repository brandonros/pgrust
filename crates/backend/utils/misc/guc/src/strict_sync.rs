//! Startup-only policy for the existing synchronous completion barrier.
//! Reuse GUC's POSTMASTER checks, including RESET, reload and child stores.

use types_error::{PgResult, FATAL};
use types_guc::{GucContext, PGC_POSTMASTER};

const FIXED_SETTINGS: &[&str] = &[
    "synchronous_commit",
    "synchronous_standby_names",
    "fsync",
    "restart_after_crash",
];

pub(crate) fn context(name: &str, ordinary: GucContext) -> GucContext {
    if guc_tables::backing::pgrust_strict_synchronous_commit()
        && FIXED_SETTINGS.contains(&name)
    {
        PGC_POSTMASTER
    } else {
        ordinary
    }
}

/// Called after postmaster configuration is loaded and before children start.
/// Child registries get the same contexts through build_variable; their normal
/// snapshot restore suppresses publication of overridden boot defaults.
pub fn configure() -> PgResult<()> {
    if !guc_tables::backing::pgrust_strict_synchronous_commit() {
        return Ok(());
    }
    use types_core::xact::{SYNCHRONOUS_COMMIT_REMOTE_APPLY, SYNCHRONOUS_COMMIT_REMOTE_FLUSH};
    let object = guc_tables::backing::pgrust_s3();
    let valid = crate::get_bool("fsync") == Some(true)
        && crate::get_bool("restart_after_crash") == Some(false)
        && matches!(crate::get_enum("synchronous_commit"),
            Some(SYNCHRONOUS_COMMIT_REMOTE_FLUSH | SYNCHRONOUS_COMMIT_REMOTE_APPLY))
        && if object {
            crate::get_enum("synchronous_commit") == Some(SYNCHRONOUS_COMMIT_REMOTE_FLUSH)
                && crate::get_string("synchronous_standby_names").flatten().is_none_or(|v| v.trim().is_empty())
        } else {
            crate::get_int("max_wal_senders").is_some_and(|n| n > 0)
                && crate::get_string("synchronous_standby_names").flatten().is_some_and(|v| !v.trim().is_empty())
        };
    if !valid {
        return elog::ereport(FATAL)
            .errmsg("invalid configuration for pgrust.strict_synchronous_commit")
            .errdetail("Requires fsync=on and restart_after_crash=off. S3 requires synchronous_commit=on and empty synchronous_standby_names; standby mode requires on/remote_apply and configured senders/standbys.")
            .finish(types_error::ErrorLocation::new(file!(), line!() as i32, "strict_sync::configure"));
    }
    crate::with_store_mut(|reg| {
        for name in FIXED_SETTINGS {
            reg.find_option_mut(name).expect("built-in strict setting").gen_mut().context = PGC_POSTMASTER;
        }
    }).expect("postmaster GUC store initialized");
    Ok(())
}
