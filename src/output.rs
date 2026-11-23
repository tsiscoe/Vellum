//! File publication for filters and repository key export.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let mut staged = tempfile::NamedTempFile::new_in(parent(path))?;
    staged.write_all(data)?;
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .with_context(|| format!("failed to publish {}", path.display()))?;
    Ok(())
}

pub fn export_key(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::create_dir_all(parent(path))?;
    write_new_key(path, data).with_context(|| format!("failed to export key to {}", path.display()))
}

#[cfg(unix)]
pub fn write_plaintext(path: &Path, data: &[u8]) -> Result<()> {
    write_atomic(path, data)
}

#[cfg(windows)]
pub fn write_plaintext(path: &Path, data: &[u8]) -> Result<()> {
    write_private_windows(path, data, true)
        .with_context(|| format!("failed to publish plaintext to {}", path.display()))
}

#[cfg(not(any(unix, windows)))]
pub fn write_plaintext(_path: &Path, _data: &[u8]) -> Result<()> {
    Err(anyhow!(
        "secure plaintext file output is unavailable on this platform"
    ))
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn write_new_key(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut staged = tempfile::NamedTempFile::new_in(parent(path))?;
    staged
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    if staged.as_file().metadata()?.permissions().mode() & 0o777 != 0o600 {
        return Err(anyhow!("unable to establish owner-only key permissions"));
    }
    staged.write_all(data)?;
    staged.as_file().sync_all()?;
    staged.persist_noclobber(path)?;
    Ok(())
}

#[cfg(windows)]
fn write_new_key(path: &Path, data: &[u8]) -> Result<()> {
    write_private_windows(path, data, false)
}

#[cfg(windows)]
fn write_private_windows(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    // Windows applies the DACL at creation, before the helper reads any secret bytes.
    // The subprocess receives data only via its pipe.
    const SECURE_EXPORT: &str = r#"
$ErrorActionPreference = 'Stop'
$destination = [IO.Path]::GetFullPath($env:VELLUM_EXPORT_DESTINATION)
$staged = [IO.Path]::Combine([IO.Path]::GetDirectoryName($destination), [IO.Path]::GetRandomFileName())
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rights = [Security.AccessControl.FileSystemRights]::FullControl
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, 'Allow'))
$created = $false
try {
    $stream = [IO.FileStream]::new($staged, 'CreateNew', $rights, 'None', 4096, 'WriteThrough', $acl)
    $created = $true
    try {
        $actual = $stream.GetAccessControl()
        $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if (!$actual.AreAccessRulesProtected -or $rules.Count -ne 1 -or
            $rules[0].IdentityReference -ne $sid -or $rules[0].AccessControlType -ne 'Allow' -or
            $rules[0].FileSystemRights -ne $rights -or
            $actual.GetOwner([Security.Principal.SecurityIdentifier]) -ne $sid) {
            throw 'Unable to verify owner-only output permissions'
        }
        [Console]::OpenStandardInput().CopyTo($stream)
        if ($stream.Length -ne [int]$env:VELLUM_EXPORT_LENGTH) { throw 'Incomplete protected output' }
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    if ($env:VELLUM_EXPORT_REPLACE -eq 'true' -and [IO.File]::Exists($destination)) {
        if ([IO.File]::GetAttributes($destination) -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Refusing to replace a plaintext reparse point'
        }
        [IO.File]::Replace($staged, $destination, [NullString]::Value, $false)
    } else {
        [IO.File]::Move($staged, $destination)
    }
    $created = $false
} finally {
    if ($created) { [IO.File]::Delete($staged) }
}
"#;
    let system_root = std::env::var_os("SystemRoot").context("Windows system root unavailable")?;
    let powershell = Path::new(&system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut child = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", SECURE_EXPORT])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .env("VELLUM_EXPORT_DESTINATION", path)
        .env("VELLUM_EXPORT_LENGTH", data.len().to_string())
        .env("VELLUM_EXPORT_REPLACE", replace.to_string())
        .env_remove("VELLUM_PASSPHRASE")
        .env_remove("VELLUM_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    let write_result = child.stdin.take().expect("piped stdin").write_all(data);
    if !child.wait()?.success() {
        return Err(anyhow!("secure Windows output failed"));
    }
    write_result?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn write_new_key(_path: &Path, _data: &[u8]) -> Result<()> {
    Err(anyhow!("secure key export is unavailable on this platform"))
}
