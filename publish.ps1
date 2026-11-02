<#
  포트폴리오 반자동 배포 스크립트

  흐름: 볼트의 포트폴리오 폴더 → content/ 로 복사 → 민감정보 검사 → 로컬 빌드 확인
        → 변경 목록 확인 후 y 입력 시에만 commit·push (push 되면 GitHub Actions가 배포)

  사용법:
    .\publish.ps1            # 검사·빌드 후 확인을 받고 push
    .\publish.ps1 -Preview   # push 없이 http://localhost:8080 미리보기
    .\publish.ps1 -Source "D:\다른\폴더"

  검사 기준:
    - publish-denylist.txt (git에 올라가지 않음): 회사명·고객명·내부 도메인 등 금지어, 한 줄에 하나
    - 마스킹: publish-denylist.txt 의 "원래단어 => 대체어" 줄, 사설·VPN IP 는 10.0.x.x 로 자동 치환 (content/ 복사본만)
    - 차단: 대체어 없는 금지어, 토큰·개인키·password= 형태, 파일 이름에 든 금지어
    - gitleaks 가 설치돼 있으면 추가로 실행
  이미지·PDF 안의 내용은 검사하지 못하므로 직접 확인해야 한다.
#>
param(
  [string]$Source = (Join-Path $env:USERPROFILE "Documents\MEGA\Obsidian\김민준\포트폴리오"),
  [switch]$Preview
)

$ErrorActionPreference = "Stop"
$Repo = $PSScriptRoot
$Content = Join-Path $Repo "content"
Set-Location $Repo

function Fail($msg) { Write-Host "중단: $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $Source)) { Fail "원본 폴더가 없습니다: $Source" }

# 1. 원격과 맞추기 (다른 PC에서 올린 변경을 덮어쓰지 않도록)
if (-not $Preview) {
  git pull --ff-only
  if ($LASTEXITCODE -ne 0) { Fail "git pull 실패. 충돌을 먼저 해결하세요." }
}

# 2. content/ 를 원본과 똑같이 맞춘다 (원본에서 지운 글은 사이트에서도 지워지도록 미러링)
if (Test-Path $Content) { Remove-Item $Content -Recurse -Force }
New-Item -ItemType Directory $Content | Out-Null
robocopy $Source $Content /E /XD .obsidian .trash /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { Fail "복사 실패 (robocopy 코드 $LASTEXITCODE)" }
Write-Host "복사 완료: $Source -> content/"

# 3. 마스킹 + 민감정보 검사 (원본 볼트는 건드리지 않고 content/ 복사본만 고친다)

# 단어 앞뒤가 영문·숫자로 이어지면 다른 단어의 일부이므로 제외한다.
# \b 는 한글도 단어 문자로 봐서 "server1에서" 같은 조사 붙은 표기를 놓치므로 쓰지 않는다.
# 뒤쪽은 영문자만 막는다: "acme2057" 처럼 숫자가 붙은 계정명도 잡기 위함.
# 앞쪽의 "\n", "\t" 같은 이스케이프 문자는 단어 경계로 본다 (코드·JSON 속 "\nacme" 대응).
function TermRegex([string]$term) {
  $re = [regex]::Escape($term)
  if ($term -match '^[A-Za-z0-9]') { $re = '(?<!(?<!\\)[A-Za-z0-9])' + $re }
  if ($term -match '[A-Za-z]$') { $re = $re + '(?![A-Za-z])' }
  elseif ($term -match '[0-9]$') { $re = $re + '(?![0-9])' }
  return '(?i)' + $re
}

$masks = @()   # @{ Term; Re; To }
$blocks = @(
  @{ Name = "개인키";       Re = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
  @{ Name = "토큰 형태";    Re = '\b(glpat-|ghp_|gho_|github_pat_|xox[abp]-|AKIA)[A-Za-z0-9_\-]{8,}' },
  @{ Name = "비밀번호 기재"; Re = '(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*\S{4,}' }
)
$denyFile = Join-Path $Repo "publish-denylist.txt"
if (Test-Path $denyFile) {
  Get-Content $denyFile -Encoding UTF8 | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") } | ForEach-Object {
    if ($_ -like "*=>*") {
      $parts = $_ -split "=>", 2
      $term = $parts[0].Trim()
      $masks += @{ Term = $term; Re = (TermRegex $term); To = $parts[1].Trim() }
    } else {
      $blocks += @{ Name = "금지어 '$_'"; Re = (TermRegex $_) }
    }
  }
} else {
  Write-Host "경고: publish-denylist.txt 가 없어 마스킹·금지어 검사를 건너뜁니다." -ForegroundColor Yellow
}
# 긴 단어부터 바꿔야 "acme.duckdns.org" 가 "acme" 규칙에 먼저 잘리지 않는다.
$masks = @($masks | Sort-Object { $_.Term.Length } -Descending)
# 마스킹 후에도 원래 단어가 남아 있으면 잡도록 차단 목록에도 넣는다.
$blocks += $masks | ForEach-Object { @{ Name = "마스킹 누락 '$($_.Term)'"; Re = $_.Re } }

# IP: 사설망(10/8, 172.16/12, 192.168/16)과 VPN 대역(100.64/10)은 자동으로 가린다.
$ipRe = '(?<![0-9.])(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d{1,3}\.\d{1,3}(?![0-9])'
$ipPartRe = '(?<![0-9.])((192\.168|172\.(1[6-9]|2\d|3[01]))\.(\d{1,3}|x|\*)(\.(\d{1,3}|x|\*))?|10\.\d{1,3}\.\d{1,3}\.(x|\*))(?![0-9])'
$blocks += @{ Name = "사설 IP"; Re = $ipRe }
$blocks += @{ Name = "사설 IP 대역"; Re = $ipPartRe }

# DuckDNS 서브도메인은 업무용 외부 주소일 가능성이 높으므로 목록에 없는 것도 가린다 (목록의 개별 대체어가 먼저 적용됨).
$duckRe = '(?i)[a-z0-9-]+\.duckdns\.org'

# 확장자 목록 대신 NUL 바이트로 텍스트/바이너리를 가른다. 확장자 없는 설정 파일(Dockerfile, .env.example 등)도 마스킹하기 위함.
function IsText($path) {
  $fs = [IO.File]::OpenRead($path)
  try { $buf = New-Object byte[] 8192; $n = $fs.Read($buf, 0, 8192) } finally { $fs.Close() }
  for ($i = 0; $i -lt $n; $i++) { if ($buf[$i] -eq 0) { return $false } }
  return $true
}
# 이미지는 내용을 검사할 수 없지만 글에 필요하므로 목록만 보여 주고, 문서·실행 파일은 차단한다.
$imageExt = ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico"
$files = Get-ChildItem $Content -Recurse -File
$textFiles = @($files | Where-Object { IsText $_.FullName })
$binFiles = @($files | Where-Object { $textFiles.FullName -notcontains $_.FullName })

$utf8 = New-Object Text.UTF8Encoding $false
$masked = 0
foreach ($f in $textFiles) {
  $text = [IO.File]::ReadAllText($f.FullName, [Text.Encoding]::UTF8)
  $orig = $text
  # 메일 주소는 개인·사내 계정이 드러나므로 전부 가린다. 연락처는 index.md 의 GitHub 링크로 대신한다.
  # 단어 마스킹보다 먼저 해야 "acme2057@..." 이 "A사2057@..." (acme => A사 규칙 기준) 으로 쪼개져 남지 않는다.
  $text = [regex]::Replace($text, '(?i)(?<![a-z0-9._%+-])[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}(?![a-z])', 'user@example.com')
  foreach ($m in $masks) { $text = [regex]::Replace($text, $m.Re, $m.To.Replace('$', '$$')) }
  $text = [regex]::Replace($text, $duckRe, 'service.example.org')
  $text = [regex]::Replace($text, $ipRe, '10.0.x.x')
  # "192.168.0.x", "172.16.5" 처럼 대역만 적은 표기도 사내망 구성을 드러내므로 가린다.
  $text = [regex]::Replace($text, $ipPartRe, '10.0.x.x')
  if ($text -ne $orig) { [IO.File]::WriteAllText($f.FullName, $text, $utf8); $masked++ }
}
Write-Host "마스킹 적용: 파일 $masked 개"

$hits = @()
foreach ($f in $binFiles) {
  $rel = $f.FullName.Substring($Content.Length + 1)
  if ($imageExt -contains $f.Extension.ToLower()) {
    Write-Host "  이미지 직접 확인 필요: $rel" -ForegroundColor Yellow
  } else {
    $hits += "{0}  [바이너리 파일 - PDF·Office·실행 파일은 내용을 가릴 수 없어 올리지 않습니다]" -f $rel
  }
}
# 파일·폴더 이름은 URL에 그대로 나오므로 따로 검사한다 (이름을 바꾸면 링크가 깨져 자동 마스킹하지 않음).
Get-ChildItem $Content -Recurse | ForEach-Object {
  $rel = $_.FullName.Substring($Content.Length + 1)
  foreach ($p in $blocks) {
    if ($_.Name -match $p.Re) { $hits += "{0}  [파일 이름에 {1} - 원본 파일 이름을 바꾸세요]" -f $rel, $p.Name }
  }
}
foreach ($file in $textFiles) {
  # 파일 전체에 먼저 맞춰 보고 걸린 규칙만 줄 단위로 다시 본다 (볼트 전체 수준에서도 수 초 안에 끝나도록).
  $whole = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
  $hitRules = @($blocks | Where-Object { $whole -match $_.Re })
  if ($hitRules.Count -eq 0) { continue }
  $lines = $whole -split "`r?`n"
  for ($i = 0; $i -lt $lines.Count; $i++) {
    foreach ($p in $hitRules) {
      if ($lines[$i] -match $p.Re) {
        $hits += "{0}:{1}  [{2}]" -f $file.FullName.Substring($Content.Length + 1), ($i + 1), $p.Name
      }
    }
  }
}
if ($hits.Count -gt 0) {
  Write-Host "민감정보로 보이는 내용이 있습니다. 원본 글을 고친 뒤 다시 실행하세요:" -ForegroundColor Red
  $hits | ForEach-Object { Write-Host "  $_" }
  exit 1
}

if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
  gitleaks dir $Content --no-banner --redact
  if ($LASTEXITCODE -ne 0) { Fail "gitleaks 가 비밀값을 찾았습니다." }
}
Write-Host "검사 통과" -ForegroundColor Green

# 4. 미리보기 모드
if ($Preview) { npx quartz build --serve; exit 0 }

# 5. 로컬 빌드로 깨진 글이 없는지 확인 (push 후 Actions에서 실패하는 것을 막기 위해)
npx quartz build
if ($LASTEXITCODE -ne 0) { Fail "빌드 실패" }

# 6. 변경 확인 후 push
git add -A
$changes = git status --short
if (-not $changes) { Write-Host "바뀐 내용이 없습니다."; exit 0 }
Write-Host "`n공개될 변경 사항:" -ForegroundColor Cyan
$changes | ForEach-Object { Write-Host "  $_" }
$answer = Read-Host "`n이 내용을 공개 사이트에 올릴까요? (y/N)"
if ($answer -ne "y") { git reset -q; Write-Host "취소했습니다. (content/ 복사본은 남아 있음)"; exit 0 }

git commit -m ("content: update {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm"))
if ($LASTEXITCODE -ne 0) { Fail "commit 실패" }
git push
if ($LASTEXITCODE -ne 0) { Fail "push 실패" }
Write-Host "push 완료. 1~2분 뒤 https://qnd1101.github.io 에 반영됩니다." -ForegroundColor Green
