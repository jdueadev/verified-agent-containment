<#
.SYNOPSIS
  Containment lab on Windows: a throwaway WSL2 distro that runs both test
  suites and a red team against a local model served by llama.cpp.

.DESCRIPTION
  Everything lives next to this script (the lab folder):
    repo.bundle      the repository (or pass -Repo with a path to a bundle or checkout)
    images\          cached Ubuntu WSL root filesystem
    models\          cached GGUF models, shared by every throwaway distro
    distros\         the throwaway distro's virtual disk
    logs\            status.txt (one line per step) and full logs
    results\<stamp>\ suite results, red-team scorecard, environment report

  Steps: preflight, get a root filesystem, import a fresh distro (root, systemd,
  no Windows interop), then inside it: install tools and CUDA, build the
  project and llama.cpp, fetch and verify the model, run the attack suite and
  live suite without waivers, serve the model and run the red team. The distro
  is unregistered at the end unless -Keep is given.

  Needs WSL 2 and, for GPU inference, an NVIDIA driver on Windows. No admin
  rights are needed. The PC is kept awake while the lab runs.

.EXAMPLE
  .\run-lab.cmd
  .\run-lab.cmd -Keep -Model unsloth/Qwen3.5-9B-GGUF:Qwen3.5-9B-Q6_K.gguf
#>
[CmdletBinding()]
param(
    [string]$Root = $PSScriptRoot,
    [string]$Repo = "",
    [string]$Model = "unsloth/Qwen3.5-9B-GGUF:Qwen3.5-9B-Q6_K.gguf",
    [string]$Name = ("containment-lab-" + (Get-Date -Format "yyyyMMdd-HHmm")),
    [ValidateSet("all", "suites", "redteam")]
    [string]$Only = "all",
    [switch]$Keep
)

# Native tools (wsl.exe, curl.exe) report through exit codes, which are checked
# explicitly. "Stop" would turn their stderr output into terminating errors.
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$env:WSL_UTF8 = "1"

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
foreach ($d in "images", "models", "distros", "logs", "results") {
    New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null
}
$status = Join-Path $Root "logs\status.txt"
$log = Join-Path $Root "logs\lab-$stamp.log"

function Say([string]$text) {
    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $text
    Write-Host $line
    Add-Content -Path $status -Value $line -Encoding UTF8
    Add-Content -Path $log -Value $line -Encoding UTF8
}

function ToWsl([string]$path) {
    $full = [System.IO.Path]::GetFullPath($path)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') { throw "Not a drive path: $full" }
    return "/mnt/" + $Matches[1].ToLower() + "/" + ($Matches[2] -replace '\\', '/')
}

# Keep the PC awake (not the display) while the lab runs; no admin needed.
Add-Type -Namespace Lab -Name Power -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern uint SetThreadExecutionState(uint flags);
'@
[void][Lab.Power]::SetThreadExecutionState([uint32]2147483649)  # ES_CONTINUOUS | ES_SYSTEM_REQUIRED

$exitCode = 1
$imported = $false
try {
    Say "START lab $stamp (distro $Name, model $Model, only $Only)"

    # 1. Preflight
    Say "STEP 1/6 preflight"
    $wslVersion = (& wsl.exe --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "WSL 2 is required (wsl.exe --version failed). Install it with: wsl --install --no-distribution" }
    Add-Content -Path $log -Value $wslVersion -Encoding UTF8
    $gpu = "none"
    $smi = Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue
    if ($smi) { $gpu = (& nvidia-smi.exe --query-gpu=name,memory.total,memory.used,driver_version --format=csv,noheader 2>&1 | Out-String).Trim() }
    $ramGb = [math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1GB, 1)
    Say "  GPU: $gpu; RAM: $ramGb GB; free on lab drive: $([math]::Round((Get-PSDrive ($Root.Substring(0,1))).Free / 1GB)) GB"
    if (-not $Repo) { $Repo = Join-Path $Root "repo.bundle" }
    if (-not (Test-Path $Repo)) { throw "No repository at $Repo (put repo.bundle next to this script or pass -Repo)" }
    foreach ($f in "lab-inside.sh") {
        if (-not (Test-Path (Join-Path $Root $f))) { throw "Missing $f next to this script" }
    }

    # 2. Root filesystem: cached, downloaded, or the WSL store image as a fallback.
    Say "STEP 2/6 Ubuntu 24.04 root filesystem"
    $rootfs = Get-ChildItem (Join-Path $Root "images") -File -Include *.tar.gz, *.wsl -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $rootfs) {
        $candidates = @(
            "https://cloud-images.ubuntu.com/wsl/releases/24.04/current/ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz",
            "https://cloud-images.ubuntu.com/wsl/noble/current/ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz"
        )
        foreach ($url in $candidates) {
            $target = Join-Path $Root ("images\" + [System.IO.Path]::GetFileName($url))
            Say "  trying $url"
            & curl.exe -fsSL --retry 3 -o "$target.part" $url
            if ($LASTEXITCODE -eq 0 -and (Get-Item "$target.part").Length -gt 100MB) {
                Move-Item -Force "$target.part" $target
                $rootfs = Get-Item $target
                break
            }
            Remove-Item -Force "$target.part" -ErrorAction SilentlyContinue
        }
    }
    $distroDir = Join-Path $Root "distros\$Name"
    if ($rootfs) {
        Say "  using $($rootfs.Name) ($([math]::Round($rootfs.Length / 1MB)) MB)"
        # 3. Import a fresh distro
        Say "STEP 3/6 import $Name"
        & wsl.exe --import $Name $distroDir $rootfs.FullName --version 2 2>&1 | Add-Content -Path $log -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { throw "wsl --import failed (see $log)" }
    } else {
        Say "  no root filesystem download worked; installing Ubuntu-24.04 from the WSL catalogue instead"
        Say "STEP 3/6 install $Name"
        & wsl.exe --install Ubuntu-24.04 --name $Name --location $distroDir --no-launch 2>&1 | Add-Content -Path $log -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { throw "wsl --install failed (see $log). Put an Ubuntu 24.04 WSL root filesystem (.tar.gz or .wsl) in $Root\images and rerun." }
    }
    $imported = $true

    # Root by default, systemd for a normal cgroup v2 tree, and no Windows
    # interop: a sandboxed process must not be able to start Windows programs.
    $wslConf = '[boot]\nsystemd=true\n[user]\ndefault=root\n[interop]\nenabled=false\nappendWindowsPath=false\n[automount]\nenabled=true\n'
    & wsl.exe -d $Name -u root -- sh -c "printf '$wslConf' > /etc/wsl.conf"
    if ($LASTEXITCODE -ne 0) { throw "could not configure $Name" }
    & wsl.exe --terminate $Name | Out-Null
    Start-Sleep -Seconds 3

    # 4-6. Everything else runs inside the distro and logs to the same folder.
    Say "STEP 4/6 inside the distro: tools, build, model, suites, red team (see logs\inside-$stamp.log)"
    $inside = ToWsl (Join-Path $Root "lab-inside.sh")
    $insideArgs = @($inside, "--lab", (ToWsl $Root), "--repo", (ToWsl $Repo), "--model", $Model, "--stamp", $stamp, "--only", $Only)
    & wsl.exe -d $Name -u root -- bash @insideArgs
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) { Say "DONE lab $stamp: results in $Root\results\$stamp" }
    else { Say "FAILED lab $stamp (exit $exitCode): see $Root\logs\inside-$stamp.log" }
}
catch {
    Say "FAILED lab $stamp at: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    if ($imported -and -not $Keep) {
        Say "STEP 6/6 unregister $Name (pass -Keep to keep it)"
        & wsl.exe --unregister $Name 2>&1 | Add-Content -Path $log -Encoding UTF8
    } elseif ($imported) {
        Say "  kept distro $Name: wsl -d $Name"
    }
    [void][Lab.Power]::SetThreadExecutionState([uint32]2147483648)  # ES_CONTINUOUS: allow sleep again
}
exit $exitCode
