# Publish existing SOC Detection Lab as a standalone public GitHub repository.
# No Git clone, no force push, no changes to other repositories.
$ErrorActionPreference = "Stop"
$owner = "Anzy1512"
$sourceRepo = "Anzy1512/Anzy1512"
$targetRepo = "Anzy1512/soc-detection-lab"
$sourceDir = "labs/soc-detection-lab"

function GetJson([string]$url) {
    $response = & gh api $url
    if ($LASTEXITCODE -ne 0) { throw "GitHub API failed: $url" }
    return (($response -join [Environment]::NewLine) | ConvertFrom-Json)
}
function Decode($entry) {
    return [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String(([string]$entry.content -replace '\s', '')))
}
function WriteFile([string]$repo, [string]$path, [string]$text,
                   [string]$branch, [string]$commit, [string]$sha = "") {
    $data = @{
        content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))
        message = $commit
        branch = $branch
    }
    if ($sha) { $data.sha = $sha }
    $tmp = Join-Path $env:TEMP ("soc-" + [Guid]::NewGuid().ToString("N") + ".json")
    try {
        [IO.File]::WriteAllText($tmp, ($data | ConvertTo-Json -Compress),
            (New-Object System.Text.UTF8Encoding($false)))
        & gh api -X PUT "repos/$repo/contents/$path" --input $tmp --silent
        if ($LASTEXITCODE -ne 0) { throw "Cannot publish $repo/$path" }
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "GitHub CLI gh is required." }
$login = ((& gh api user --jq '.login') -join "").Trim()
if ($LASTEXITCODE -ne 0 -or $login -ne $owner) { throw "Authenticate using gh auth login as $owner." }
$existing = @(& gh repo list $owner --limit 1000 --json name --jq '.[].name')
if ($LASTEXITCODE -ne 0) { throw "Could not list GitHub repositories." }

$createdNow = $false
if ($existing -notcontains "soc-detection-lab") {
    & gh repo create $targetRepo --public --add-readme --description "Offline Python SOC detection lab with synthetic authentication logs"
    if ($LASTEXITCODE -ne 0) { throw "Repository creation failed." }
    $createdNow = $true
}
$rawMeta = & gh repo view $targetRepo --json visibility,defaultBranchRef
if ($LASTEXITCODE -ne 0) { throw "Cannot inspect destination repository." }
$meta = ($rawMeta -join [Environment]::NewLine) | ConvertFrom-Json
if ($meta.visibility -ne "PUBLIC") { throw "Destination is not public; no visibility changes performed." }
$branch = [string]$meta.defaultBranchRef.name
if (-not $branch) { throw "Destination has no default branch." }
$treeUrl = "repos/{0}/git/trees/{1}?recursive=1" -f $targetRepo, $branch
$filesPresent = @(& gh api $treeUrl --jq '.tree[].path')
if ($LASTEXITCODE -ne 0) { throw "Cannot inspect destination files." }

$copy = @(
    "README.md", "detector.py", "main.py", "data/auth_events.jsonl",
    "tests/test_detector.py", "sample_output.json",
    "docs/triage-runbook.md", "docs/analyst-case-study.md"
)
foreach ($path in $copy) {
    $src = GetJson "repos/$sourceRepo/contents/$sourceDir/$path"
    $wanted = Decode $src
    $sha = ""
    if ($filesPresent -contains $path) {
        $dest = GetJson "repos/$targetRepo/contents/$path"
        $current = Decode $dest
        if ($current -ceq $wanted) { Write-Host "UNCHANGED: $path"; continue }
        if (-not ($createdNow -and $path -eq "README.md" -and
                  $current.Trim() -eq "# soc-detection-lab")) {
            throw "Existing content differs at $path. Stopped to avoid overwriting."
        }
        $sha = [string]$dest.sha
    }
    WriteFile $targetRepo $path $wanted $branch ("docs: publish " + $path) $sha
    Write-Host "PUBLISHED: $path" -ForegroundColor Green
}

$ci = @'
name: SOC Lab Tests
on:
  push:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m unittest discover -s tests -v
      - run: |
          python main.py --output findings.json
          python -c "import json; x=json.load(open('findings.json')); assert x['input_events']==13 and x['alert_count']==3"
'@
$ignore = @'
__pycache__/
*.py[cod]
.venv/
findings.json
.pytest_cache/
'@
$extras = @{
    ".github/workflows/python-tests.yml" = $ci
    ".gitignore" = $ignore
}
foreach ($path in $extras.Keys) {
    if ($filesPresent -contains $path) {
        $present = GetJson "repos/$targetRepo/contents/$path"
        if ((Decode $present) -ceq $extras[$path]) { Write-Host "UNCHANGED: $path"; continue }
        Write-Warning "Existing $path differs; preserved."
        continue
    }
    try {
        WriteFile $targetRepo $path $extras[$path] $branch ("chore: add " + $path)
        Write-Host "PUBLISHED: $path" -ForegroundColor Green
    } catch { Write-Warning "Optional $path could not be added: $_" }
}

$profile = GetJson "repos/$sourceRepo/contents/README.md"
$before = Decode $profile
$old = "[SOC Detection Lab](labs/soc-detection-lab/README.md)"
$new = "[SOC Detection Lab](https://github.com/$targetRepo)"
if ($before.Contains($old)) {
    WriteFile $sourceRepo "README.md" ($before.Replace($old, $new)) "main" "docs: link standalone SOC lab" ([string]$profile.sha)
    Write-Host "PROFILE LINK UPDATED" -ForegroundColor Green
} elseif ($before.Contains($new)) {
    Write-Host "PROFILE LINK ALREADY CORRECT" -ForegroundColor Green
} else {
    Write-Warning "Profile link not modified: source link changed since preparation."
}
Write-Host "LIVE: https://github.com/$targetRepo" -ForegroundColor Cyan
Write-Host "PROFILE: https://github.com/$sourceRepo" -ForegroundColor Cyan
