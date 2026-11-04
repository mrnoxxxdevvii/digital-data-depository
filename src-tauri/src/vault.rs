use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::State;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"DDDVAULT";
const VERSION: u32 = 2;
const SLOT_SIZE: usize = 2048;
const DATA_START: u64 = 4096;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_MAC_OFFSET: usize = 140;
const HEADER_MAC_END: usize = 172;
const HEADER_HASH_OFFSET: usize = 172;
const HEADER_HASH_END: usize = 204;
const ARGON_M_COST: u32 = 262_144;
const ARGON_T_COST: u32 = 4;
const ARGON_P_COST: u32 = 1;
const ARGON_M_MIN: u32 = 65_536;
const ARGON_M_MAX: u32 = 1_048_576;
const ARGON_T_MIN: u32 = 3;
const ARGON_T_MAX: u32 = 10;
const ARGON_P_MIN: u32 = 1;
const ARGON_P_MAX: u32 = 8;
const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 1024;
const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_NAME_LEN: usize = 200;
const MAX_INDEX_SIZE: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const AUTHOR_URL: &str = "https://github.com/mrnoxxxdevvii";

mod memlock {
    use std::ffi::c_void;

    #[cfg(windows)]
    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualLock(address: *mut c_void, size: usize) -> i32;
        fn VirtualUnlock(address: *mut c_void, size: usize) -> i32;
    }

    #[cfg(unix)]
    extern "C" {
        fn mlock(address: *const c_void, size: usize) -> i32;
        fn munlock(address: *const c_void, size: usize) -> i32;
    }

    pub fn lock(address: *mut u8, size: usize) {
        #[cfg(windows)]
        unsafe {
            let _ = VirtualLock(address as *mut c_void, size);
        }
        #[cfg(unix)]
        unsafe {
            let _ = mlock(address as *const c_void, size);
        }
        #[cfg(not(any(windows, unix)))]
        let _ = (address, size);
    }

    pub fn unlock(address: *mut u8, size: usize) {
        #[cfg(windows)]
        unsafe {
            let _ = VirtualUnlock(address as *mut c_void, size);
        }
        #[cfg(unix)]
        unsafe {
            let _ = munlock(address as *const c_void, size);
        }
        #[cfg(not(any(windows, unix)))]
        let _ = (address, size);
    }
}

mod file_lock {
    use std::fs::File;

    #[cfg(windows)]
    mod imp {
        use std::ffi::c_void;
        use std::fs::File;
        use std::os::windows::io::AsRawHandle;

        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;

        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            event: *mut c_void,
        }

        #[link(name = "kernel32")]
        extern "system" {
            fn LockFileEx(
                file: *mut c_void,
                flags: u32,
                reserved: u32,
                bytes_low: u32,
                bytes_high: u32,
                overlapped: *mut Overlapped,
            ) -> i32;
        }

        pub fn try_lock(file: &File) -> bool {
            let mut overlapped = Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event: std::ptr::null_mut(),
            };
            unsafe {
                LockFileEx(
                    file.as_raw_handle() as *mut c_void,
                    LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                ) != 0
            }
        }
    }

    #[cfg(unix)]
    mod imp {
        use std::fs::File;
        use std::os::unix::io::AsRawFd;

        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;

        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }

        pub fn try_lock(file: &File) -> bool {
            unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
        }
    }

    #[cfg(not(any(windows, unix)))]
    mod imp {
        use std::fs::File;

        pub fn try_lock(_: &File) -> bool {
            true
        }
    }

    pub fn try_lock(file: &File) -> bool {
        imp::try_lock(file)
    }
}

struct SecretKey {
    bytes: Box<[u8; KEY_LEN]>,
}

impl SecretKey {
    fn zeroed() -> Self {
        let mut bytes = Box::new([0u8; KEY_LEN]);
        memlock::lock(bytes.as_mut_ptr(), KEY_LEN);
        Self { bytes }
    }

    fn from_slice(data: &[u8]) -> Result<Self, String> {
        if data.len() != KEY_LEN {
            return Err("Wrong password or damaged vault.".to_string());
        }
        let mut key = Self::zeroed();
        key.bytes.copy_from_slice(data);
        Ok(key)
    }
}

impl Deref for SecretKey {
    type Target = [u8; KEY_LEN];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.as_mut().zeroize();
        memlock::unlock(self.bytes.as_mut_ptr(), KEY_LEN);
    }
}

#[derive(Clone)]
struct Header {
    generation: u64,
    salt: [u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    wrap_nonce: [u8; NONCE_LEN],
    wrapped_key: [u8; KEY_LEN + TAG_LEN],
    vault_id: [u8; 16],
    index_offset: u64,
    index_len: u64,
    mac: [u8; KEY_LEN],
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; KEY_LEN] {
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        block_key[..KEY_LEN].copy_from_slice(&Sha256::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= block_key[index];
        outer_pad[index] ^= block_key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let mut result = [0u8; KEY_LEN];
    result.copy_from_slice(&outer.finalize());
    block_key.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    result
}

fn header_mac(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; KEY_LEN] {
    let mut mac_key = Sha256::new();
    mac_key.update(key);
    mac_key.update(b"DDD-HDR-MAC-v2");
    let mut derived = mac_key.finalize();
    let mac = hmac_sha256(&derived, data);
    derived.as_mut_slice().zeroize();
    mac
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

impl Header {
    fn encode(&self, key: &[u8; KEY_LEN]) -> [u8; SLOT_SIZE] {
        let mut out = [0u8; SLOT_SIZE];
        out[0..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&VERSION.to_le_bytes());
        out[12..20].copy_from_slice(&self.generation.to_le_bytes());
        out[20..36].copy_from_slice(&self.salt);
        out[36..40].copy_from_slice(&self.m_cost.to_le_bytes());
        out[40..44].copy_from_slice(&self.t_cost.to_le_bytes());
        out[44..48].copy_from_slice(&self.p_cost.to_le_bytes());
        out[48..60].copy_from_slice(&self.wrap_nonce);
        out[60..108].copy_from_slice(&self.wrapped_key);
        out[108..124].copy_from_slice(&self.vault_id);
        out[124..132].copy_from_slice(&self.index_offset.to_le_bytes());
        out[132..140].copy_from_slice(&self.index_len.to_le_bytes());
        let mac = header_mac(key, &out[0..HEADER_MAC_OFFSET]);
        out[HEADER_MAC_OFFSET..HEADER_MAC_END].copy_from_slice(&mac);
        let digest = Sha256::digest(&out[0..HEADER_HASH_OFFSET]);
        out[HEADER_HASH_OFFSET..HEADER_HASH_END].copy_from_slice(&digest);
        out
    }

    fn verify_mac(&self, key: &[u8; KEY_LEN]) -> bool {
        let mut raw = [0u8; HEADER_MAC_OFFSET];
        raw[0..8].copy_from_slice(MAGIC);
        raw[8..12].copy_from_slice(&VERSION.to_le_bytes());
        raw[12..20].copy_from_slice(&self.generation.to_le_bytes());
        raw[20..36].copy_from_slice(&self.salt);
        raw[36..40].copy_from_slice(&self.m_cost.to_le_bytes());
        raw[40..44].copy_from_slice(&self.t_cost.to_le_bytes());
        raw[44..48].copy_from_slice(&self.p_cost.to_le_bytes());
        raw[48..60].copy_from_slice(&self.wrap_nonce);
        raw[60..108].copy_from_slice(&self.wrapped_key);
        raw[108..124].copy_from_slice(&self.vault_id);
        raw[124..132].copy_from_slice(&self.index_offset.to_le_bytes());
        raw[132..140].copy_from_slice(&self.index_len.to_le_bytes());
        let mac = header_mac(key, &raw);
        raw.zeroize();
        ct_eq(&mac, &self.mac)
    }

    fn decode(bytes: &[u8]) -> Option<Header> {
        if bytes.len() < SLOT_SIZE || &bytes[0..8] != MAGIC {
            return None;
        }
        if u32::from_le_bytes(bytes[8..12].try_into().ok()?) != VERSION {
            return None;
        }
        let digest = Sha256::digest(&bytes[0..HEADER_HASH_OFFSET]);
        if digest.as_slice() != &bytes[HEADER_HASH_OFFSET..HEADER_HASH_END] {
            return None;
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[20..36]);
        let mut wrap_nonce = [0u8; NONCE_LEN];
        wrap_nonce.copy_from_slice(&bytes[48..60]);
        let mut wrapped_key = [0u8; KEY_LEN + TAG_LEN];
        wrapped_key.copy_from_slice(&bytes[60..108]);
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&bytes[108..124]);
        let mut mac = [0u8; KEY_LEN];
        mac.copy_from_slice(&bytes[HEADER_MAC_OFFSET..HEADER_MAC_END]);
        Some(Header {
            generation: u64::from_le_bytes(bytes[12..20].try_into().ok()?),
            salt,
            m_cost: u32::from_le_bytes(bytes[36..40].try_into().ok()?),
            t_cost: u32::from_le_bytes(bytes[40..44].try_into().ok()?),
            p_cost: u32::from_le_bytes(bytes[44..48].try_into().ok()?),
            wrap_nonce,
            wrapped_key,
            vault_id,
            index_offset: u64::from_le_bytes(bytes[124..132].try_into().ok()?),
            index_len: u64::from_le_bytes(bytes[132..140].try_into().ok()?),
            mac,
        })
    }
}

fn params_valid(header: &Header) -> bool {
    (ARGON_M_MIN..=ARGON_M_MAX).contains(&header.m_cost)
        && (ARGON_T_MIN..=ARGON_T_MAX).contains(&header.t_cost)
        && (ARGON_P_MIN..=ARGON_P_MAX).contains(&header.p_cost)
}

fn lock_file(file: &File) -> Result<(), String> {
    if file_lock::try_lock(file) {
        Ok(())
    } else {
        Err("This vault is already open in another process.".to_string())
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn kek_aad(vault_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = b"DDD-KEK-v1".to_vec();
    aad.extend_from_slice(vault_id);
    aad
}

fn index_aad(vault_id: &[u8; 16], generation: u64, offset: u64, len: u64) -> Vec<u8> {
    let mut aad = b"DDD-IDX-v2".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.extend_from_slice(&offset.to_le_bytes());
    aad.extend_from_slice(&len.to_le_bytes());
    aad
}

fn next_generation(generation: u64) -> Result<u64, String> {
    generation
        .checked_add(1)
        .ok_or_else(|| "The vault header is damaged.".to_string())
}

fn object_aad(vault_id: &[u8; 16], id: &str) -> Vec<u8> {
    let mut aad = b"DDD-OBJ-v1".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn derive_kek(
    password: &str,
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<SecretKey, String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|_| "Invalid vault parameters.".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = SecretKey::zeroed();
    argon
        .hash_password_into(password.as_bytes(), salt, key.bytes.as_mut())
        .map_err(|_| "Key derivation failed.".to_string())?;
    Ok(key)
}

fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Cipher init failed.".to_string())?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| "Encryption failed.".to_string())
}

fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if nonce.len() != NONCE_LEN {
        return Err("Damaged data.".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Cipher init failed.".to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| "Damaged data.".to_string())?;
    Ok(Zeroizing::new(plaintext))
}

fn read_header(file: &mut File) -> Result<(Header, u8), String> {
    let file_len = file
        .metadata()
        .map_err(|_| "Could not read the vault file.".to_string())?
        .len();
    if file_len < DATA_START {
        return Err("This is not a DDD vault.".to_string());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "Could not read the vault file.".to_string())?;
    let mut buf = [0u8; SLOT_SIZE * 2];
    file.read_exact(&mut buf)
        .map_err(|_| "Could not read the vault file.".to_string())?;
    let first = Header::decode(&buf[0..SLOT_SIZE]);
    let second = Header::decode(&buf[SLOT_SIZE..]);
    let (header, slot) = match (first, second) {
        (Some(a), Some(b)) => {
            if b.generation > a.generation {
                (b, 1)
            } else {
                (a, 0)
            }
        }
        (Some(a), None) => (a, 0),
        (None, Some(b)) => (b, 1),
        (None, None) => return Err("This is not a DDD vault or it is damaged.".to_string()),
    };
    if !params_valid(&header) {
        return Err("The vault header is damaged.".to_string());
    }
    let index_end = header
        .index_offset
        .checked_add(header.index_len)
        .ok_or_else(|| "The vault header is damaged.".to_string())?;
    if header.index_offset < DATA_START
        || header.index_len < (NONCE_LEN + TAG_LEN) as u64
        || header.index_len > MAX_INDEX_SIZE
        || index_end > file_len
    {
        return Err("The vault header is damaged.".to_string());
    }
    Ok((header, slot))
}

#[derive(Serialize, Deserialize, Clone)]
struct VaultIndex {
    version: u32,
    created_at: u64,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    id: String,
    name: String,
    size: u64,
    sha256: String,
    nonce: String,
    offset: u64,
    len: u64,
    created_at: u64,
    kind: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.id.zeroize();
        self.name.zeroize();
        self.sha256.zeroize();
        self.nonce.zeroize();
        self.kind.zeroize();
    }
}

#[derive(Serialize, Clone)]
pub struct EntryView {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub created_at: u64,
    pub kind: String,
}

impl Drop for EntryView {
    fn drop(&mut self) {
        self.id.zeroize();
        self.name.zeroize();
        self.sha256.zeroize();
        self.kind.zeroize();
    }
}

#[derive(Serialize, Clone)]
pub struct Snapshot {
    pub name: String,
    pub created_at: u64,
    pub total_size: u64,
    pub entries: Vec<EntryView>,
}

#[derive(Serialize)]
pub struct AddResult {
    pub added: u32,
    pub failed: Vec<String>,
    pub snapshot: Snapshot,
}

#[derive(Serialize)]
pub struct VerifyFailure {
    pub name: String,
    pub error: String,
}

#[derive(Serialize)]
pub struct VerifyReport {
    pub total: u32,
    pub ok: u32,
    pub failures: Vec<VerifyFailure>,
}

#[derive(Serialize)]
pub struct CompactResult {
    pub reclaimed: u64,
    pub snapshot: Snapshot,
}

pub struct Session {
    path: PathBuf,
    file: File,
    header: Header,
    active_slot: u8,
    key: SecretKey,
    index: VaultIndex,
}

impl Session {
    fn new(
        path: &Path,
        file: File,
        header: Header,
        active_slot: u8,
        key: SecretKey,
        index: VaultIndex,
    ) -> Self {
        Self {
            path: path.to_path_buf(),
            file,
            header,
            active_slot,
            key,
            index,
        }
    }
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "Password must be at least {} characters.",
            MIN_PASSWORD_LEN
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err("Password is too long.".to_string());
    }
    Ok(())
}

fn clean_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("Enter a file name.".to_string());
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err("File name is too long.".to_string());
    }
    if name.chars().any(|c| {
        c.is_control()
            || c == '/'
            || c == '\\'
            || matches!(
                c,
                '\u{200E}'
                    | '\u{200F}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            )
    }) {
        return Err("File name contains unsupported characters.".to_string());
    }
    Ok(name.to_string())
}

fn kind_for(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

fn has_duplicate_ids(index: &VaultIndex) -> bool {
    let mut ids = std::collections::HashSet::with_capacity(index.entries.len());
    index.entries.iter().any(|entry| !ids.insert(entry.id.as_str()))
}

fn read_index(file: &mut File, header: &Header, key: &[u8; KEY_LEN]) -> Result<VaultIndex, String> {
    let index_len: usize = header
        .index_len
        .try_into()
        .map_err(|_| "The vault index is damaged.".to_string())?;
    file.seek(SeekFrom::Start(header.index_offset))
        .map_err(|_| "Could not read the vault index.".to_string())?;
    let mut block = vec![0u8; index_len];
    file.read_exact(&mut block)
        .map_err(|_| "Could not read the vault index.".to_string())?;
    let plaintext = decrypt(
        key,
        &block[0..NONCE_LEN],
        &block[NONCE_LEN..],
        &index_aad(
            &header.vault_id,
            header.generation,
            header.index_offset,
            header.index_len,
        ),
    )
    .map_err(|_| "The vault index is damaged.".to_string())?;
    let index: VaultIndex =
        serde_json::from_slice(&plaintext).map_err(|_| "The vault index is damaged.".to_string())?;
    if index.version != VERSION || index.entries.len() > MAX_ENTRIES || has_duplicate_ids(&index) {
        return Err("The vault index is damaged.".to_string());
    }
    let file_len = file
        .metadata()
        .map_err(|_| "Could not read the vault file.".to_string())?
        .len();
    for entry in &index.entries {
        let digest_ok = entry.sha256.len() == 64
            && entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit());
        let nonce_ok = entry.nonce.len() == NONCE_LEN * 2
            && entry.nonce.bytes().all(|byte| byte.is_ascii_hexdigit());
        if entry.id.is_empty()
            || entry.id.len() > 64
            || entry.name.trim().is_empty()
            || entry.name.chars().count() > MAX_NAME_LEN
            || entry.size > MAX_FILE_SIZE
            || entry.len < (NONCE_LEN + TAG_LEN) as u64
            || entry.len > MAX_FILE_SIZE + (NONCE_LEN + TAG_LEN) as u64
            || entry.offset < DATA_START
            || !digest_ok
            || !nonce_ok
            || entry
                .offset
                .checked_add(entry.len)
                .map(|end| end > file_len)
                .unwrap_or(true)
        {
            return Err("The vault index is damaged.".to_string());
        }
    }
    Ok(index)
}

fn create_new_file(path: &Path, read: bool, write: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(read).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn read_source_file(path: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let mut limited = file.take(MAX_FILE_SIZE + 1);
    let mut data = Vec::new();
    limited.read_to_end(&mut data)?;
    Ok(Zeroizing::new(data))
}

pub fn create_depository(path: &Path, password: &str) -> Result<Session, String> {
    validate_password(password)?;
    let mut file = create_new_file(path, true, true).map_err(|_| {
        "Could not create the vault file. If it exists, choose another name.".to_string()
    })?;
    if let Err(err) = lock_file(&file) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(err);
    }
    match init_new_depository(&mut file, password) {
        Ok((header, key, index)) => Ok(Session::new(path, file, header, 0, key, index)),
        Err(err) => {
            drop(file);
            let _ = std::fs::remove_file(path);
            Err(err)
        }
    }
}

fn init_new_depository(
    file: &mut File,
    password: &str,
) -> Result<(Header, SecretKey, VaultIndex), String> {
    let salt: [u8; SALT_LEN] = random_bytes();
    let vault_id: [u8; 16] = random_bytes();
    let kek = derive_kek(password, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
    let mut key = SecretKey::zeroed();
    OsRng.fill_bytes(key.bytes.as_mut());
    let wrap_nonce: [u8; NONCE_LEN] = random_bytes();
    let wrapped = encrypt(&kek, &wrap_nonce, &key[..], &kek_aad(&vault_id))?;
    let mut wrapped_key = [0u8; KEY_LEN + TAG_LEN];
    wrapped_key.copy_from_slice(&wrapped);

    file.set_len(DATA_START)
        .map_err(|_| "Could not write the vault file.".to_string())?;

    let index = VaultIndex {
        version: VERSION,
        created_at: now_ms(),
        entries: Vec::new(),
    };
    let index_nonce: [u8; NONCE_LEN] = random_bytes();
    let index_json = Zeroizing::new(
        serde_json::to_vec(&index).map_err(|_| "Could not write the vault index.".to_string())?,
    );
    let index_len = (NONCE_LEN + index_json.len() + TAG_LEN) as u64;
    let ciphertext = encrypt(
        &key,
        &index_nonce,
        &index_json[..],
        &index_aad(&vault_id, 1, DATA_START, index_len),
    )?;
    file.seek(SeekFrom::Start(DATA_START))
        .map_err(|_| "Could not write the vault file.".to_string())?;
    file.write_all(&index_nonce)
        .and_then(|_| file.write_all(&ciphertext))
        .map_err(|_| "Could not write the vault file.".to_string())?;

    let mut header = Header {
        generation: 1,
        salt,
        m_cost: ARGON_M_COST,
        t_cost: ARGON_T_COST,
        p_cost: ARGON_P_COST,
        wrap_nonce,
        wrapped_key,
        vault_id,
        index_offset: DATA_START,
        index_len,
        mac: [0u8; KEY_LEN],
    };
    let encoded = header.encode(&key);
    header
        .mac
        .copy_from_slice(&encoded[HEADER_MAC_OFFSET..HEADER_MAC_END]);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&encoded))
        .and_then(|_| file.sync_all())
        .map_err(|_| "Could not write the vault file.".to_string())?;

    Ok((header, key, index))
}

pub fn open_depository(path: &Path, password: &str) -> Result<Session, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| "Could not open the vault file.".to_string())?;
    lock_file(&file)?;
    let (header, active_slot) = read_header(&mut file)?;
    let kek = derive_kek(
        password,
        &header.salt,
        header.m_cost,
        header.t_cost,
        header.p_cost,
    )?;
    let wrapped = decrypt(
        &kek,
        &header.wrap_nonce,
        &header.wrapped_key,
        &kek_aad(&header.vault_id),
    )
    .map_err(|_| "Wrong password or damaged vault.".to_string())?;
    let key = SecretKey::from_slice(&wrapped)?;
    if !header.verify_mac(&key) {
        return Err("The vault header is damaged.".to_string());
    }
    let index = read_index(&mut file, &header, &key)?;
    Ok(Session::new(path, file, header, active_slot, key, index))
}

impl Session {
    pub fn snapshot(&self) -> Snapshot {
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault.ddd")
            .to_string();
        let entries = self
            .index
            .entries
            .iter()
            .map(|entry| EntryView {
                id: entry.id.clone(),
                name: entry.name.clone(),
                size: entry.size,
                sha256: entry.sha256.clone(),
                created_at: entry.created_at,
                kind: entry.kind.clone(),
            })
            .collect();
        Snapshot {
            name,
            created_at: self.index.created_at,
            total_size: self.index.entries.iter().map(|entry| entry.size).sum(),
            entries,
        }
    }

    fn write_header_slot(&mut self, slot: u8, header: &mut Header) -> Result<(), String> {
        let encoded = header.encode(&self.key);
        header
            .mac
            .copy_from_slice(&encoded[HEADER_MAC_OFFSET..HEADER_MAC_END]);
        self.file
            .seek(SeekFrom::Start(slot as u64 * SLOT_SIZE as u64))
            .and_then(|_| self.file.write_all(&encoded))
            .and_then(|_| self.file.sync_data())
            .map_err(|_| "Could not update the vault header.".to_string())
    }

    fn save_index(&mut self) -> Result<(), String> {
        let json = Zeroizing::new(
            serde_json::to_vec(&self.index)
                .map_err(|_| "Could not write the vault index.".to_string())?,
        );
        let index_len = (NONCE_LEN + json.len() + TAG_LEN) as u64;
        if index_len > MAX_INDEX_SIZE {
            return Err("The vault index is full.".to_string());
        }
        let generation = next_generation(self.header.generation)?;
        let offset = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|_| "Could not write the vault index.".to_string())?;
        let nonce: [u8; NONCE_LEN] = random_bytes();
        let ciphertext = encrypt(
            &self.key,
            &nonce,
            &json[..],
            &index_aad(&self.header.vault_id, generation, offset, index_len),
        )?;
        self.file
            .write_all(&nonce)
            .and_then(|_| self.file.write_all(&ciphertext))
            .and_then(|_| self.file.sync_data())
            .map_err(|_| "Could not write the vault index.".to_string())?;
        let mut next = self.header.clone();
        next.generation = generation;
        next.index_offset = offset;
        next.index_len = index_len;
        let slot = 1 - self.active_slot;
        self.write_header_slot(slot, &mut next)?;
        self.active_slot = slot;
        self.header = next;
        Ok(())
    }

    pub fn add_file(&mut self, name: &str, data: &[u8]) -> Result<(), String> {
        let name = clean_name(name)?;
        if data.len() as u64 > MAX_FILE_SIZE {
            return Err("File is larger than 512 MB.".to_string());
        }
        if self.index.entries.len() >= MAX_ENTRIES {
            return Err("The vault has reached its entry limit.".to_string());
        }
        let id = Uuid::new_v4().to_string();
        let digest = hex::encode(Sha256::digest(data));
        let nonce: [u8; NONCE_LEN] = random_bytes();
        let ciphertext = encrypt(
            &self.key,
            &nonce,
            data,
            &object_aad(&self.header.vault_id, &id),
        )?;
        let offset = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|_| "Could not write the vault data.".to_string())?;
        self.file
            .write_all(&nonce)
            .and_then(|_| self.file.write_all(&ciphertext))
            .and_then(|_| self.file.sync_data())
            .map_err(|_| "Could not write the vault data.".to_string())?;
        let kind = kind_for(&name);
        self.index.entries.push(Entry {
            id: id.clone(),
            name,
            size: data.len() as u64,
            sha256: digest,
            nonce: hex::encode(nonce),
            offset,
            len: (NONCE_LEN + ciphertext.len()) as u64,
            created_at: now_ms(),
            kind,
        });
        if let Err(err) = self.save_index() {
            self.index.entries.retain(|entry| entry.id != id);
            return Err(err);
        }
        Ok(())
    }

    pub fn rename_file(&mut self, id: &str, new_name: &str) -> Result<(), String> {
        let name = clean_name(new_name)?;
        let entry = self
            .index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| "File not found.".to_string())?;
        let previous = std::mem::replace(&mut entry.name, name.clone());
        entry.kind = kind_for(&name);
        if let Err(err) = self.save_index() {
            if let Some(entry) = self.index.entries.iter_mut().find(|entry| entry.id == id) {
                entry.name = previous;
            }
            return Err(err);
        }
        Ok(())
    }

    pub fn delete_file(&mut self, id: &str) -> Result<(), String> {
        let position = self
            .index
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| "File not found.".to_string())?;
        let removed = self.index.entries.remove(position);
        if let Err(err) = self.save_index() {
            self.index.entries.insert(position, removed);
            return Err(err);
        }
        Ok(())
    }

    pub fn read_file(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let entry = self
            .index
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| "File not found.".to_string())?
            .clone();
        let file_len = self
            .file
            .metadata()
            .map_err(|_| "Could not read the vault file.".to_string())?
            .len();
        let end = entry
            .offset
            .checked_add(entry.len)
            .ok_or_else(|| "The vault data is damaged.".to_string())?;
        if entry.offset < DATA_START || entry.len < (NONCE_LEN + TAG_LEN) as u64 || end > file_len {
            return Err("The vault data is damaged.".to_string());
        }
        let mut block = vec![0u8; entry.len as usize];
        let mut file = &self.file;
        file.seek(SeekFrom::Start(entry.offset))
            .and_then(|_| file.read_exact(&mut block))
            .map_err(|_| "Could not read the vault data.".to_string())?;
        let nonce = hex::decode(&entry.nonce).map_err(|_| "The vault data is damaged.".to_string())?;
        if !ct_eq(&nonce, &block[..NONCE_LEN]) {
            return Err("Integrity check failed. The file is damaged.".to_string());
        }
        let plaintext = decrypt(
            &self.key,
            &nonce,
            &block[NONCE_LEN..],
            &object_aad(&self.header.vault_id, &entry.id),
        )
        .map_err(|_| "Integrity check failed. The file is damaged.".to_string())?;
        let digest = hex::encode(Sha256::digest(&plaintext[..]));
        if digest != entry.sha256 {
            return Err("Integrity check failed. The file is damaged.".to_string());
        }
        Ok(plaintext)
    }

    pub fn verify(&self) -> VerifyReport {
        let mut report = VerifyReport {
            total: self.index.entries.len() as u32,
            ok: 0,
            failures: Vec::new(),
        };
        for entry in &self.index.entries {
            match self.read_file(&entry.id) {
                Ok(_) => report.ok += 1,
                Err(err) => report.failures.push(VerifyFailure {
                    name: entry.name.clone(),
                    error: err,
                }),
            }
        }
        report
    }

    pub fn change_password(&mut self, current: &str, next: &str) -> Result<(), String> {
        validate_password(next)?;
        let current_kek = derive_kek(
            current,
            &self.header.salt,
            self.header.m_cost,
            self.header.t_cost,
            self.header.p_cost,
        )?;
        let unwrapped = decrypt(
            &current_kek,
            &self.header.wrap_nonce,
            &self.header.wrapped_key,
            &kek_aad(&self.header.vault_id),
        )
        .map_err(|_| "Current password is incorrect.".to_string())?;
        if unwrapped[..] != self.key[..] {
            return Err("Current password is incorrect.".to_string());
        }

        let salt: [u8; SALT_LEN] = random_bytes();
        let kek = derive_kek(next, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
        let mut new_key = SecretKey::zeroed();
        OsRng.fill_bytes(new_key.bytes.as_mut());
        let wrap_nonce: [u8; NONCE_LEN] = random_bytes();
        let wrapped = encrypt(
            &kek,
            &wrap_nonce,
            &new_key[..],
            &kek_aad(&self.header.vault_id),
        )?;
        let mut wrapped_key = [0u8; KEY_LEN + TAG_LEN];
        wrapped_key.copy_from_slice(&wrapped);

        let mut header = self.header.clone();
        header.generation = next_generation(self.header.generation)?;
        header.salt = salt;
        header.m_cost = ARGON_M_COST;
        header.t_cost = ARGON_T_COST;
        header.p_cost = ARGON_P_COST;
        header.wrap_nonce = wrap_nonce;
        header.wrapped_key = wrapped_key;
        header.mac = [0u8; KEY_LEN];

        let temp_path = self.temp_path();
        let built = self.rebuild_file(&temp_path, &new_key, header);
        let (file, header, index) = match built {
            Ok(value) => value,
            Err(err) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(err);
            }
        };
        self.install_rebuild(temp_path, file, header, index, Some(new_key))?;
        Ok(())
    }

    pub fn compact(&mut self) -> Result<u64, String> {
        let old_len = self
            .file
            .metadata()
            .map_err(|_| "Could not read the vault file.".to_string())?
            .len();
        let mut header = self.header.clone();
        header.generation = next_generation(self.header.generation)?;
        header.mac = [0u8; KEY_LEN];
        let temp_path = self.temp_path();
        let built = self.rebuild_file(&temp_path, &self.key, header);
        let (file, header, index) = match built {
            Ok(value) => value,
            Err(err) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(err);
            }
        };
        self.install_rebuild(temp_path, file, header, index, None)?;
        let new_len = self
            .file
            .metadata()
            .map_err(|_| "Could not read the vault file.".to_string())?
            .len();
        Ok(old_len.saturating_sub(new_len))
    }

    fn temp_path(&self) -> PathBuf {
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault.ddd");
        self.path
            .with_file_name(format!(".{}.{}.tmp", file_name, Uuid::new_v4()))
    }

    fn rebuild_file(
        &self,
        temp_path: &Path,
        key: &SecretKey,
        mut header: Header,
    ) -> Result<(File, Header, VaultIndex), String> {
        let mut temp = create_new_file(temp_path, true, true)
            .map_err(|_| "Could not create a temporary vault file.".to_string())?;
        lock_file(&temp)?;
        temp.set_len(DATA_START)
            .map_err(|_| "Could not write the temporary vault file.".to_string())?;
        let mut entries = Vec::with_capacity(self.index.entries.len());
        for entry in &self.index.entries {
            let data = self.read_file(&entry.id)?;
            let nonce: [u8; NONCE_LEN] = random_bytes();
            let ciphertext = encrypt(
                key,
                &nonce,
                &data[..],
                &object_aad(&header.vault_id, &entry.id),
            )?;
            let offset = temp
                .seek(SeekFrom::End(0))
                .map_err(|_| "Could not write the temporary vault file.".to_string())?;
            temp.write_all(&nonce)
                .and_then(|_| temp.write_all(&ciphertext))
                .map_err(|_| "Could not write the temporary vault file.".to_string())?;
            let mut copy = entry.clone();
            copy.nonce = hex::encode(nonce);
            copy.offset = offset;
            copy.len = (NONCE_LEN + ciphertext.len()) as u64;
            entries.push(copy);
        }
        let mut new_index = self.index.clone();
        new_index.entries = entries;
        let json = Zeroizing::new(
            serde_json::to_vec(&new_index)
                .map_err(|_| "Could not write the vault index.".to_string())?,
        );
        let index_len = (NONCE_LEN + json.len() + TAG_LEN) as u64;
        if index_len > MAX_INDEX_SIZE {
            return Err("The vault index is full.".to_string());
        }
        let index_offset = temp
            .seek(SeekFrom::End(0))
            .map_err(|_| "Could not write the vault index.".to_string())?;
        let index_nonce: [u8; NONCE_LEN] = random_bytes();
        let index_ciphertext = encrypt(
            key,
            &index_nonce,
            &json[..],
            &index_aad(&header.vault_id, header.generation, index_offset, index_len),
        )?;
        temp.write_all(&index_nonce)
            .and_then(|_| temp.write_all(&index_ciphertext))
            .map_err(|_| "Could not write the vault index.".to_string())?;
        header.index_offset = index_offset;
        header.index_len = index_len;
        let encoded = header.encode(key);
        header
            .mac
            .copy_from_slice(&encoded[HEADER_MAC_OFFSET..HEADER_MAC_END]);
        temp.seek(SeekFrom::Start(0))
            .and_then(|_| temp.write_all(&encoded))
            .and_then(|_| temp.seek(SeekFrom::Start(SLOT_SIZE as u64)))
            .and_then(|_| temp.write_all(&encoded))
            .and_then(|_| temp.sync_all())
            .map_err(|_| "Could not write the temporary vault file.".to_string())?;
        Ok((temp, header, new_index))
    }

    fn install_rebuild(
        &mut self,
        temp_path: PathBuf,
        file: File,
        header: Header,
        index: VaultIndex,
        key: Option<SecretKey>,
    ) -> Result<(), String> {
        if std::fs::rename(&temp_path, &self.path).is_err() {
            drop(file);
            let _ = std::fs::remove_file(&temp_path);
            return Err("Could not replace the vault file.".to_string());
        }
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            if let Ok(directory) = File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        self.file = file;
        self.header = header;
        self.active_slot = 0;
        self.index = index;
        if let Some(key) = key {
            self.key = key;
        }
        Ok(())
    }
}

struct IdleState {
    last_active: Instant,
    limit: Duration,
}

pub struct AppState {
    session: Mutex<Option<Session>>,
    failures: Mutex<u32>,
    idle: Mutex<IdleState>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            failures: Mutex::new(0),
            idle: Mutex::new(IdleState {
                last_active: Instant::now(),
                limit: Duration::from_secs(600),
            }),
        }
    }
}

impl AppState {
    pub fn set_auto_lock(&self, minutes: u64) {
        if let Ok(mut idle) = self.idle.lock() {
            idle.limit = Duration::from_secs(minutes.clamp(1, 30) * 60);
            idle.last_active = Instant::now();
        }
    }

    pub fn touch(&self) {
        if let Ok(mut idle) = self.idle.lock() {
            idle.last_active = Instant::now();
        }
    }

    pub fn idle_expired(&self) -> bool {
        let expired = match self.idle.lock() {
            Ok(idle) => idle.last_active.elapsed() >= idle.limit,
            Err(_) => false,
        };
        if !expired {
            return false;
        }
        let mut guard = match self.session.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        if guard.is_none() {
            if let Ok(mut idle) = self.idle.lock() {
                idle.last_active = Instant::now();
            }
            return false;
        }
        match self.idle.lock() {
            Ok(idle) if idle.last_active.elapsed() >= idle.limit => {}
            _ => return false,
        }
        guard.take();
        if let Ok(mut idle) = self.idle.lock() {
            idle.last_active = Instant::now();
        }
        true
    }
}

#[tauri::command]
pub fn set_auto_lock(state: State<'_, AppState>, minutes: u64) {
    state.set_auto_lock(minutes);
}

#[tauri::command]
pub fn touch_vault(state: State<'_, AppState>) {
    state.touch();
}

fn snapshot_or_error(state: &AppState) -> Result<Snapshot, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    guard
        .as_ref()
        .map(Session::snapshot)
        .ok_or_else(|| "No vault is open.".to_string())
}

#[tauri::command]
pub async fn pick_vault() -> Result<Option<String>, String> {
    let picked = rfd::FileDialog::new()
        .add_filter("DDD vault", &["ddd"])
        .pick_file();
    Ok(picked.map(|path| path.to_string_lossy().to_string()))
}

#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    password: String,
) -> Result<Option<Snapshot>, String> {
    validate_password(&password)?;
    let password = Zeroizing::new(password);
    let picked = rfd::FileDialog::new()
        .add_filter("DDD vault", &["ddd"])
        .set_file_name("vault.ddd")
        .save_file();
    let mut path = match picked {
        Some(path) => path,
        None => return Ok(None),
    };
    if path.extension().is_none() {
        path = path.with_extension("ddd");
    }
    let session = tauri::async_runtime::spawn_blocking(move || {
        create_depository(&path, &password)
    })
    .await
    .map_err(|_| "Could not create the vault.".to_string())??;
    let snapshot = session.snapshot();
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    *guard = Some(session);
    Ok(Some(snapshot))
}

#[tauri::command]
pub async fn open_vault(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> Result<Snapshot, String> {
    let path_buf = PathBuf::from(path);
    let password = Zeroizing::new(password);
    let result = tauri::async_runtime::spawn_blocking(move || {
        open_depository(&path_buf, &password)
    })
    .await
    .map_err(|_| "Could not open the vault.".to_string())?;
    match result {
        Ok(session) => {
            let snapshot = session.snapshot();
            let mut guard = state
                .session
                .lock()
                .map_err(|_| "The vault is not available.".to_string())?;
            *guard = Some(session);
            if let Ok(mut failures) = state.failures.lock() {
                *failures = 0;
            }
            Ok(snapshot)
        }
        Err(err) => {
            let attempts = {
                let mut failures = state
                    .failures
                    .lock()
                    .map_err(|_| "The vault is not available.".to_string())?;
                *failures = failures.saturating_add(1);
                *failures
            };
            let delay = Duration::from_millis((attempts as u64 * 300).min(2_000));
            tauri::async_runtime::spawn_blocking(move || std::thread::sleep(delay))
                .await
                .ok();
            Err(err)
        }
    }
}

#[tauri::command]
pub async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    guard.take();
    Ok(())
}

#[tauri::command]
pub async fn vault_snapshot(state: State<'_, AppState>) -> Result<Snapshot, String> {
    snapshot_or_error(&state)
}

#[tauri::command]
pub async fn add_files(state: State<'_, AppState>) -> Result<AddResult, String> {
    let picked = rfd::FileDialog::new().pick_files().unwrap_or_default();
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "No vault is open.".to_string())?;
    let mut added = 0u32;
    let mut failed = Vec::new();
    for path in picked {
        let name = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name.to_string(),
            None => {
                failed.push("A file with an unsupported name was skipped.".to_string());
                continue;
            }
        };
        let data = match read_source_file(&path) {
            Ok(data) => data,
            Err(_) => {
                failed.push(format!("{}: could not read file.", name));
                continue;
            }
        };
        if data.len() as u64 > MAX_FILE_SIZE {
            failed.push(format!("{}: larger than 512 MB.", name));
            continue;
        }
        match session.add_file(&name, &data) {
            Ok(()) => added += 1,
            Err(err) => failed.push(format!("{}: {}", name, err)),
        }
    }
    Ok(AddResult {
        added,
        failed,
        snapshot: session.snapshot(),
    })
}

fn canonical_for_compare(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let parent = path.parent()?.canonicalize().ok()?;
    Some(parent.join(path.file_name()?))
}

fn same_file(left: &Path, right: &Path) -> bool {
    let left = match canonical_for_compare(left) {
        Some(path) => path,
        None => return false,
    };
    let right = match canonical_for_compare(right) {
        Some(path) => path,
        None => return false,
    };
    #[cfg(windows)]
    {
        left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

#[tauri::command]
pub async fn export_entry(
    state: State<'_, AppState>,
    id: String,
) -> Result<Option<String>, String> {
    let name = {
        let guard = state
            .session
            .lock()
            .map_err(|_| "The vault is not available.".to_string())?;
        let session = guard
            .as_ref()
            .ok_or_else(|| "No vault is open.".to_string())?;
        session
            .index
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.name.clone())
            .ok_or_else(|| "File not found.".to_string())?
    };
    let picked = rfd::FileDialog::new().set_file_name(&name).save_file();
    let path = match picked {
        Some(path) => path,
        None => return Ok(None),
    };
    let guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "No vault is open.".to_string())?;
    if same_file(&path, &session.path) {
        return Err("Choose a different destination. That is the vault file.".to_string());
    }
    let data = session.read_file(&id)?;
    let temp_path = path.with_file_name(format!(".{}.{}.tmp", name, Uuid::new_v4()));
    let written = (|| -> std::io::Result<()> {
        let mut file = create_new_file(&temp_path, false, true)?;
        file.write_all(&data)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, &path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp_path);
        return Err("Could not write the file.".to_string());
    }
    Ok(Some(name))
}

#[tauri::command]
pub async fn rename_entry(
    state: State<'_, AppState>,
    id: String,
    name: String,
) -> Result<Snapshot, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "No vault is open.".to_string())?;
    session.rename_file(&id, &name)?;
    Ok(session.snapshot())
}

#[tauri::command]
pub async fn delete_entry(
    state: State<'_, AppState>,
    id: String,
) -> Result<Snapshot, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "No vault is open.".to_string())?;
    session.delete_file(&id)?;
    Ok(session.snapshot())
}

#[tauri::command]
pub async fn change_password(
    state: State<'_, AppState>,
    current: String,
    next: String,
) -> Result<(), String> {
    let current = Zeroizing::new(current);
    let next = Zeroizing::new(next);
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "No vault is open.".to_string())?;
    session.change_password(&current, &next)
}

#[tauri::command]
pub fn open_author_profile() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", AUTHOR_URL])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|_| "Could not open the browser.".to_string())?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(AUTHOR_URL)
            .spawn()
            .map_err(|_| "Could not open the browser.".to_string())?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(AUTHOR_URL)
            .spawn()
            .map_err(|_| "Could not open the browser.".to_string())?;
        return Ok(());
    }
    #[allow(unreachable_code)]
    Err("Opening links is not supported on this platform.".to_string())
}

#[tauri::command]
pub async fn verify_vault(state: State<'_, AppState>) -> Result<VerifyReport, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "No vault is open.".to_string())?;
    Ok(session.verify())
}

#[tauri::command]
pub async fn compact_vault(state: State<'_, AppState>) -> Result<CompactResult, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "The vault is not available.".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "No vault is open.".to_string())?;
    let reclaimed = session.compact()?;
    Ok(CompactResult {
        reclaimed,
        snapshot: session.snapshot(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ddd-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_path() -> PathBuf {
        test_dir().join("vault.ddd")
    }

    const PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn create_add_read_roundtrip() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session.add_file("notes.txt", b"hello depository").unwrap();
        assert_eq!(session.snapshot().entries.len(), 1);
        let data = session.read_file(&session.snapshot().entries[0].id).unwrap();
        assert_eq!(&*data, b"hello depository");
        drop(session);

        let session = open_depository(&path, PASSWORD).unwrap();
        assert_eq!(session.snapshot().entries.len(), 1);
        let id = session.snapshot().entries[0].id.clone();
        assert_eq!(&*session.read_file(&id).unwrap(), b"hello depository");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let path = sample_path();
        let session = create_depository(&path, PASSWORD).unwrap();
        drop(session);
        let error = match open_depository(&path, "wrong password 123") {
            Ok(_) => panic!("a wrong password was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, "Wrong password or damaged vault.");
    }

    #[test]
    fn plaintext_is_not_stored() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session
            .add_file("secret-name.txt", b"unique-plaintext-marker-12345")
            .unwrap();
        drop(session);
        let bytes = fs::read(&path).unwrap();
        let haystack = String::from_utf8_lossy(&bytes);
        assert!(!haystack.contains("secret-name.txt"));
        assert!(!haystack.contains("unique-plaintext-marker-12345"));
    }

    #[test]
    fn tampering_is_detected() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session.add_file("data.bin", &[7u8; 1024]).unwrap();
        let entry = session.index.entries[0].clone();
        drop(session);

        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(entry.offset + NONCE_LEN as u64 + 10))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xff;
        file.seek(SeekFrom::Start(entry.offset + NONCE_LEN as u64 + 10))
            .unwrap();
        file.write_all(&byte).unwrap();
        drop(file);

        let session = open_depository(&path, PASSWORD).unwrap();
        assert!(session.read_file(&entry.id).is_err());
        let report = session.verify();
        assert_eq!(report.total, 1);
        assert_eq!(report.ok, 0);
        assert_eq!(report.failures.len(), 1);
    }

    #[test]
    fn object_nonce_prefix_is_checked() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session.add_file("data.bin", &[7u8; 256]).unwrap();
        let entry = session.index.entries[0].clone();
        drop(session);

        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(entry.offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xff;
        file.seek(SeekFrom::Start(entry.offset)).unwrap();
        file.write_all(&byte).unwrap();
        drop(file);

        let session = open_depository(&path, PASSWORD).unwrap();
        assert!(session.read_file(&entry.id).is_err());
        let report = session.verify();
        assert_eq!(report.ok, 0);
        assert_eq!(report.failures.len(), 1);
    }

    #[test]
    fn duplicate_entry_ids_are_rejected() {
        let entry = Entry {
            id: "duplicate".to_string(),
            name: "a.txt".to_string(),
            size: 0,
            sha256: "0".repeat(64),
            nonce: "0".repeat(NONCE_LEN * 2),
            offset: DATA_START,
            len: (NONCE_LEN + TAG_LEN) as u64,
            created_at: 0,
            kind: "txt".to_string(),
        };
        let index = VaultIndex {
            version: VERSION,
            created_at: 0,
            entries: vec![entry.clone(), entry],
        };
        assert!(has_duplicate_ids(&index));
    }

    #[test]
    fn rename_and_delete() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session.add_file("old.txt", b"abc").unwrap();
        let id = session.snapshot().entries[0].id.clone();
        session.rename_file(&id, "new.txt").unwrap();
        assert_eq!(session.snapshot().entries[0].name, "new.txt");
        session.delete_file(&id).unwrap();
        assert!(session.snapshot().entries.is_empty());
        drop(session);
        let session = open_depository(&path, PASSWORD).unwrap();
        assert!(session.snapshot().entries.is_empty());
    }

    #[test]
    fn password_change_rekeys_the_vault() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session.add_file("data.txt", b"payload").unwrap();
        let old_wrapped = session.header.wrapped_key;
        let old_salt = session.header.salt;
        let old_nonce = session.index.entries[0].nonce.clone();
        session
            .change_password(PASSWORD, "another strong password")
            .unwrap();
        assert_ne!(session.header.wrapped_key, old_wrapped);
        assert_ne!(session.header.salt, old_salt);
        assert_ne!(session.index.entries[0].nonce, old_nonce);
        drop(session);

        assert!(open_depository(&path, PASSWORD).is_err());
        let session = open_depository(&path, "another strong password").unwrap();
        let id = session.snapshot().entries[0].id.clone();
        assert_eq!(&*session.read_file(&id).unwrap(), b"payload");
    }

    #[test]
    fn header_mac_rejects_pointer_tampering() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session.add_file("data.txt", b"payload").unwrap();
        let mut header = session.header.clone();
        assert!(header.verify_mac(&session.key));
        header.index_offset += 16;
        assert!(!header.verify_mac(&session.key));
        header.index_offset -= 16;
        header.generation += 1;
        assert!(!header.verify_mac(&session.key));
    }

    #[test]
    fn idle_watchdog_drops_session() {
        let path = sample_path();
        let session = create_depository(&path, PASSWORD).unwrap();
        let state = AppState::default();
        *state.session.lock().unwrap() = Some(session);
        state.set_auto_lock(10);
        assert!(!state.idle_expired());
        {
            let mut idle = state.idle.lock().unwrap();
            idle.limit = Duration::from_secs(0);
            idle.last_active = Instant::now() - Duration::from_secs(1);
        }
        assert!(state.idle_expired());
        assert!(state.session.lock().unwrap().is_none());
        assert!(!state.idle_expired());
    }

    #[test]
    fn export_destination_cannot_be_the_vault() {
        let path = sample_path();
        let session = create_depository(&path, PASSWORD).unwrap();
        assert!(same_file(&path, &path));
        let other = path.with_file_name("export.txt");
        assert!(!same_file(&path, &other));
        drop(session);
    }

    #[test]
    fn compact_removes_deleted_data() {
        let path = sample_path();
        let mut session = create_depository(&path, PASSWORD).unwrap();
        session.add_file("keep.txt", &[1u8; 4096]).unwrap();
        session.add_file("drop.txt", &[2u8; 4096]).unwrap();
        let drop_id = session
            .snapshot()
            .entries
            .iter()
            .find(|entry| entry.name == "drop.txt")
            .unwrap()
            .id
            .clone();
        session.delete_file(&drop_id).unwrap();
        let before = fs::metadata(&path).unwrap().len();
        let reclaimed = session.compact().unwrap();
        let after = fs::metadata(&path).unwrap().len();
        assert!(reclaimed > 0);
        assert!(after < before);
        let id = session.snapshot().entries[0].id.clone();
        assert_eq!(&*session.read_file(&id).unwrap(), &[1u8; 4096]);
        drop(session);
        let session = open_depository(&path, PASSWORD).unwrap();
        assert_eq!(session.snapshot().entries.len(), 1);
        assert_eq!(session.snapshot().entries[0].name, "keep.txt");
    }

    #[test]
    fn reject_short_password_and_bad_names() {
        let path = sample_path();
        assert!(create_depository(&path, "short").is_err());
        let mut session = create_depository(&path, PASSWORD).unwrap();
        assert!(session.add_file("", b"x").is_err());
        assert!(session.add_file("bad/name.txt", b"x").is_err());
        assert!(session.add_file("bidi\u{202E}name.txt", b"x").is_err());
        assert!(session.add_file("name.txt", &[0u8; 16]).is_ok());
    }

    #[test]
    fn create_does_not_delete_an_existing_file() {
        let path = sample_path();
        fs::write(&path, b"existing data").unwrap();
        assert!(create_depository(&path, PASSWORD).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"existing data");
    }

    #[test]
    fn second_open_is_rejected_while_first_is_live() {
        let path = sample_path();
        let session = create_depository(&path, PASSWORD).unwrap();
        let error = match open_depository(&path, PASSWORD) {
            Ok(_) => panic!("a second session was allowed"),
            Err(error) => error,
        };
        assert_eq!(error, "This vault is already open in another process.");
        drop(session);
        assert!(open_depository(&path, PASSWORD).is_ok());
    }

    #[test]
    fn kdf_parameters_are_bounded() {
        let mut header = Header {
            generation: 1,
            salt: [0u8; SALT_LEN],
            m_cost: ARGON_M_COST,
            t_cost: ARGON_T_COST,
            p_cost: ARGON_P_COST,
            wrap_nonce: [0u8; NONCE_LEN],
            wrapped_key: [0u8; KEY_LEN + TAG_LEN],
            vault_id: [0u8; 16],
            index_offset: DATA_START,
            index_len: 32,
            mac: [0u8; KEY_LEN],
        };
        assert!(params_valid(&header));
        header.m_cost = 32_768;
        assert!(!params_valid(&header));
        header.m_cost = 2_097_152;
        assert!(!params_valid(&header));
        header.m_cost = ARGON_M_COST;
        header.t_cost = 2;
        assert!(!params_valid(&header));
        header.t_cost = 11;
        assert!(!params_valid(&header));
        header.t_cost = ARGON_T_COST;
        header.p_cost = 9;
        assert!(!params_valid(&header));
    }
}
