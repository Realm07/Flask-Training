$ErrorActionPreference = "Stop"

git init

$baseDate = Get-Date "2026-02-10 15:00:00"

$folders = Get-ChildItem -Directory | 
           Where-Object { $_.Name -match "^Day_" } | 
           Sort-Object Name

$offset = 0

foreach ($folder in $folders) {

    $current = $baseDate.AddDays($offset)

    # Skip Sunday
    if ($current.DayOfWeek -eq "Sunday") {
        $offset++
        $current = $baseDate.AddDays($offset)
    }

    $minute = Get-Random -Minimum 0 -Maximum 59
    $commitTime = $current.Date.AddHours(15).AddMinutes($minute)

    git add $folder.Name

    $env:GIT_AUTHOR_DATE    = $commitTime.ToString("yyyy-MM-dd HH:mm:ss")
    $env:GIT_COMMITTER_DATE = $commitTime.ToString("yyyy-MM-dd HH:mm:ss")

    git commit -m "$($folder.Name) - Flask Training Progress"

    Write-Host "Committed $($folder.Name) on $commitTime"

    $offset++
}

# Final commit for root files
git add README.md .gitignore

$finalDate = Get-Date "2026-02-17 15:25:00"

$env:GIT_AUTHOR_DATE    = $finalDate.ToString("yyyy-MM-dd HH:mm:ss")
$env:GIT_COMMITTER_DATE = $finalDate.ToString("yyyy-MM-dd HH:mm:ss")

git commit -m "Project initialization and documentation"

Write-Host "Done."
