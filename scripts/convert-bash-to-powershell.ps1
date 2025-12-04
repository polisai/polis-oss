# Script to convert remaining bash command blocks to PowerShell in documentation
# This script updates .github/instructions/refactoring.instructions.md

$filePath = "e:\polisai\proxy\.github\instructions\refactoring.instructions.md"

Write-Host "Converting bash commands to PowerShell in: $filePath" -ForegroundColor Cyan

# Read the file content
$content = Get-Content $filePath -Raw

# Common bash to PowerShell replacements
$replacements = @{
    # Basic commands
    'mkdir -p' = 'New-Item -ItemType Directory -Force -Path'
    'touch' = 'New-Item -ItemType File -Force -Path'
    'cat ' = 'Get-Content '
    'ls -la' = 'Get-ChildItem'
    'ls ' = 'Get-ChildItem '
    'rm -rf' = 'Remove-Item -Recurse -Force'
    'rm -f' = 'Remove-Item -Force'
    'cp -r' = 'Copy-Item -Recurse -Force -Path'
    'mv ' = 'Move-Item -Force'
    'find . -name' = 'Get-ChildItem -Recurse -Filter'
    'find . -type f' = 'Get-ChildItem -File -Recurse'
    'grep -r' = 'Get-ChildItem -Recurse | Select-String -Pattern'
    'grep -q' = 'Select-String -Quiet -Pattern'
    'tree -L' = 'tree'
    'chmod +x' = '# PowerShell scripts are executable by default'
    'test -d' = 'Test-Path'
    'test ! -d' = '-not (Test-Path'
    'echo "' = 'Write-Host "'
    'wc -l' = 'Measure-Object -Line'
    './scripts/' = '& .\scripts\'
    '.sh' = '.ps1'
}

# Replace code block markers
$content = $content -replace '```bash', '```powershell'

# Apply replacements
foreach ($key in $replacements.Keys) {
    $content = $content -replace [regex]::Escape($key), $replacements[$key]
}

# Save the updated content
Set-Content -Path $filePath -Value $content

Write-Host "✅ Conversion complete!" -ForegroundColor Green
Write-Host "File updated: $filePath" -ForegroundColor Yellow
Write-Host "`n⚠️  Note: This is an automated conversion. Please review the changes manually." -ForegroundColor Yellow
Write-Host "Some complex bash constructs may need manual adjustment." -ForegroundColor Yellow
