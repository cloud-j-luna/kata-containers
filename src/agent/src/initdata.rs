//! # Initdata Module
//!
//! This module will do the following things if a proper initdata device with initdata exists.
//! 1. Parse the initdata block device and extract the config files to [`INITDATA_PATH`].
//! 2. Return the initdata and the policy (if any).

// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[cfg(feature = "init-data")]
use std::os::unix::fs::FileTypeExt;

use anyhow::{bail, Context, Result};
use async_compression::tokio::bufread::GzipDecoder;
use base64::{engine::general_purpose::STANDARD, Engine};
use const_format::concatcp;
use kata_types::initdata::InitData;
use sha2::{Digest, Sha256, Sha384, Sha512};
use slog::Logger;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// This is the target directory to store the extracted initdata.
pub const INITDATA_PATH: &str = "/run/confidential-containers/initdata";

const AA_CONFIG_KEY: &str = "aa.toml";
const CDH_CONFIG_KEY: &str = "cdh.toml";
const POLICY_KEY: &str = "policy.rego";

/// Initdata key for the container image registry authentication file.
///
/// When present, its value (in `containers-auth.json` / `.dockerconfigjson`
/// format) is written verbatim to `<INITDATA_PATH>/auth.json` so image-rs can
/// pull images from private registries inside the guest without a KBS, e.g. via
/// `image_registry_auth = "file:///run/confidential-containers/initdata/auth.json"`.
/// Because the initdata is measured, the credentials do not affect the guest
/// launch measurement.
const AUTH_FILE_KEY: &str = "auth.json";

/// The path of initdata toml
pub const INITDATA_TOML_PATH: &str = concatcp!(INITDATA_PATH, "/initdata.toml");

/// The path of AA's config file
pub const AA_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/aa.toml");

/// The path of CDH's config file
pub const CDH_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/cdh.toml");

/// Magic number of initdata device
#[cfg(feature = "init-data")]
pub const INITDATA_MAGIC_NUMBER: &[u8] = b"initdata";

/// initdata device with disk type 'vd*'
#[cfg(feature = "init-data")]
const INITDATA_PREFIX_DISK_VDX: &str = "vd";

/// initdata device with disk type 'sd*'
#[cfg(feature = "init-data")]
const INITDATA_PREFIX_DISK_SDX: &str = "sd";

#[cfg(not(feature = "init-data"))]
async fn detect_initdata_device(logger: &Logger) -> Result<Option<String>> {
    debug!(logger, "Initdata is disabled");
    Ok(None)
}

#[cfg(feature = "init-data")]
async fn detect_initdata_device(logger: &Logger) -> Result<Option<String>> {
    let dev_dir = Path::new("/dev");
    let mut read_dir = tokio::fs::read_dir(dev_dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let filename = entry.file_name();
        let filename = filename.to_string_lossy();
        debug!(logger, "Initdata check device `{filename}`");

        // Currently there're two disk types supported:
        // virtio-blk (vd*) and virtio-scsi (sd*)
        if !filename.starts_with(INITDATA_PREFIX_DISK_VDX)
            && !filename.starts_with(INITDATA_PREFIX_DISK_SDX)
        {
            continue;
        }

        let path = entry.path();

        debug!(logger, "Initdata find potential device: `{path:?}`");
        let metadata = std::fs::metadata(path.clone())?;
        if !metadata.file_type().is_block_device() {
            continue;
        }

        let mut file = tokio::fs::File::open(&path).await?;
        let mut magic = [0; 8];
        match file.read_exact(&mut magic).await {
            Ok(_) => {
                debug!(
                    logger,
                    "Initdata read device `{filename}` first 8 bytes: {magic:?}"
                );
                if magic == INITDATA_MAGIC_NUMBER {
                    let path = path.as_path().to_string_lossy().to_string();
                    debug!(logger, "Found initdata device {path}");
                    return Ok(Some(path));
                }
            }
            Err(e) => debug!(logger, "Initdata read device `{filename}` failed: {e:?}"),
        }
    }

    Ok(None)
}

pub async fn read_initdata(device_path: &str) -> Result<Vec<u8>> {
    let initdata_devfile = tokio::fs::File::open(device_path).await?;
    let mut buf_reader = tokio::io::BufReader::new(initdata_devfile);
    // skip the magic number "initdata"
    buf_reader.seek(std::io::SeekFrom::Start(8)).await?;

    let mut len_buf = [0u8; 8];
    buf_reader.read_exact(&mut len_buf).await?;
    let length = u64::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0; length];
    buf_reader.read_exact(&mut buf).await?;
    let mut gzip_decoder = GzipDecoder::new(&buf[..]);

    let mut initdata = Vec::new();
    let _ = gzip_decoder.read_to_end(&mut initdata).await?;
    Ok(initdata)
}

pub struct InitdataReturnValue {
    pub _digest: Vec<u8>,
    pub _policy: Option<String>,
}

/// Materialize the configuration/data files carried by `initdata` into
/// `base_dir`.
///
/// Each entry is written to `base_dir/<key>`, mirroring the initdata `[data]`
/// key as the file name so that consumers can reference well-known paths (e.g.
/// [`AA_CONFIG_PATH`], [`CDH_CONFIG_PATH`], and `<INITDATA_PATH>/auth.json`).
/// Missing keys are skipped. `policy.rego` is intentionally not written here: it
/// is returned to the caller instead.
///
/// The registry authentication file holds credentials, so it is created with
/// owner-only (0600) permissions to avoid exposing them to other processes in
/// the guest.
async fn materialize_initdata_files(
    logger: &Logger,
    initdata: &InitData,
    base_dir: &Path,
) -> Result<()> {
    if let Some(config) = initdata.get_coco_data(AA_CONFIG_KEY) {
        tokio::fs::write(base_dir.join(AA_CONFIG_KEY), config)
            .await
            .context("write aa config failed")?;
        info!(logger, "write AA config from initdata");
    }

    if let Some(config) = initdata.get_coco_data(CDH_CONFIG_KEY) {
        tokio::fs::write(base_dir.join(CDH_CONFIG_KEY), config)
            .await
            .context("write cdh config failed")?;
        info!(logger, "write CDH config from initdata");
    }

    if let Some(auth) = initdata.get_coco_data(AUTH_FILE_KEY) {
        let path = base_dir.join(AUTH_FILE_KEY);
        tokio::fs::write(&path, auth)
            .await
            .context("write registry auth file failed")?;
        // The auth file contains registry credentials; restrict it to the
        // owner (root) only.
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .await
            .context("set registry auth file permissions failed")?;
        info!(logger, "write registry auth file from initdata");
    }

    Ok(())
}

pub async fn initialize_initdata(logger: &Logger) -> Result<Option<InitdataReturnValue>> {
    let logger = logger.new(o!("subsystem" => "initdata"));
    let Some(initdata_device) = detect_initdata_device(&logger).await? else {
        info!(
            logger,
            "Initdata device not found, skip initdata initialization"
        );
        return Ok(None);
    };

    tokio::fs::create_dir_all(INITDATA_PATH)
        .await
        .inspect_err(|e| error!(logger, "Failed to create initdata dir: {e:?}"))?;

    let initdata_content = read_initdata(&initdata_device)
        .await
        .inspect_err(|e| error!(logger, "Failed to read initdata: {e:?}"))?;

    let initdata: InitData =
        toml::from_slice(&initdata_content).context("parse initdata failed")?;
    info!(logger, "Initdata version: {}", initdata.version());
    initdata.validate()?;

    tokio::fs::write(INITDATA_TOML_PATH, &initdata_content)
        .await
        .context("write initdata toml failed")?;

    let _digest = match initdata.algorithm() {
        "sha256" => Sha256::digest(&initdata_content).to_vec(),
        "sha384" => Sha384::digest(&initdata_content).to_vec(),
        "sha512" => Sha512::digest(&initdata_content).to_vec(),
        others => bail!("Unsupported hash algorithm {others}"),
    };

    materialize_initdata_files(&logger, &initdata, Path::new(INITDATA_PATH)).await?;

    debug!(logger, "Initdata digest: {}", STANDARD.encode(&_digest));

    let res = InitdataReturnValue {
        _digest,
        _policy: initdata.get_coco_data(POLICY_KEY).cloned(),
    };

    Ok(Some(res))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_types::initdata::InitData;

    const INITDATA_IMG_PATH: &str = "testdata/initdata.img";
    const INITDATA_PLAINTEXT: &[u8] = b"some content";
    const TEST_AUTH_JSON: &str = r#"{"auths":{"ghcr.io":{"auth":"dXNlcjpwYXNz"}}}"#;

    fn test_logger() -> slog::Logger {
        slog::Logger::root(slog::Discard, o!())
    }

    #[tokio::test]
    async fn parse_initdata() {
        let initdata = read_initdata(INITDATA_IMG_PATH).await.unwrap();
        assert_eq!(initdata, INITDATA_PLAINTEXT);
    }

    // The registry auth file must be written verbatim and, because it holds
    // credentials, with owner-only (0600) permissions.
    #[tokio::test]
    async fn test_materialize_registry_auth_content_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut initdata = InitData::new("sha384", "0.1.0");
        initdata.insert_data(AUTH_FILE_KEY, TEST_AUTH_JSON);

        materialize_initdata_files(&test_logger(), &initdata, dir.path())
            .await
            .unwrap();

        let path = dir.path().join(AUTH_FILE_KEY);
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, TEST_AUTH_JSON, "auth file content must match initdata");

        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "registry auth file must be owner-only (0600)"
        );
    }

    // All present keys are materialized to their well-known file names.
    #[tokio::test]
    async fn test_materialize_writes_all_present_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut initdata = InitData::new("sha384", "0.1.0");
        initdata.insert_data(AA_CONFIG_KEY, "aa-config");
        initdata.insert_data(CDH_CONFIG_KEY, "cdh-config");
        initdata.insert_data(AUTH_FILE_KEY, TEST_AUTH_JSON);

        materialize_initdata_files(&test_logger(), &initdata, dir.path())
            .await
            .unwrap();

        assert_eq!(
            tokio::fs::read_to_string(dir.path().join(AA_CONFIG_KEY))
                .await
                .unwrap(),
            "aa-config"
        );
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join(CDH_CONFIG_KEY))
                .await
                .unwrap(),
            "cdh-config"
        );
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join(AUTH_FILE_KEY))
                .await
                .unwrap(),
            TEST_AUTH_JSON
        );
    }

    // Absent keys (including the new auth key) must not create files: this
    // guards against regressing existing deployments that supply only aa/cdh.
    #[tokio::test]
    async fn test_materialize_skips_absent_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut initdata = InitData::new("sha384", "0.1.0");
        initdata.insert_data(CDH_CONFIG_KEY, "cdh-config");

        materialize_initdata_files(&test_logger(), &initdata, dir.path())
            .await
            .unwrap();

        assert!(dir.path().join(CDH_CONFIG_KEY).exists());
        assert!(
            !dir.path().join(AUTH_FILE_KEY).exists(),
            "auth file must not be created when absent from initdata"
        );
        assert!(!dir.path().join(AA_CONFIG_KEY).exists());
    }

    // An empty [data] map is a no-op and must not error.
    #[tokio::test]
    async fn test_materialize_empty_initdata_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let initdata = InitData::new("sha384", "0.1.0");

        materialize_initdata_files(&test_logger(), &initdata, dir.path())
            .await
            .unwrap();

        assert!(!dir.path().join(AUTH_FILE_KEY).exists());
        assert!(!dir.path().join(AA_CONFIG_KEY).exists());
        assert!(!dir.path().join(CDH_CONFIG_KEY).exists());
    }
}
