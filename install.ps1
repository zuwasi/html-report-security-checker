$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path ".git" -PathType Container)) {
    Write-Error "Error: this directory is not a Git repository."
    exit 1
}

$hookDirectory = Join-Path ".git" "hooks"
New-Item -ItemType Directory -Path $hookDirectory -Force | Out-Null
Copy-Item "hooks/pre-commit" $hookDirectory -Force
Copy-Item "hooks/pre-push" $hookDirectory -Force

if (-not $IsWindows) {
    chmod +x (Join-Path $hookDirectory "pre-commit") (Join-Path $hookDirectory "pre-push")
}

Write-Host "Git hooks installed! Pre-commit and pre-push hooks are now active."
