# ============================================================
# FullScan.ps1 - Network Disk Analyzer
# Scans folder, finds old/large files, generates reports
# Shows how much space can be freed
# ============================================================

# ===== SETTINGS =====
$SharePath  = "G:\net\share"
$DaysOld    = 730
$MinSizeMB  = 50
$OutputDir  = "C:\temp\reports"
$HtmlDir    = "C:\temp\html_reports"
$SummaryCSV = "C:\temp\SummaryReport.csv"
$LogFile    = "C:\temp\FullScanLog.txt"
$CutoffDate = (Get-Date).AddDays(-$DaysOld)
$Deadline   = (Get-Date).AddDays(14).ToString("dd.MM.yyyy")

# Create output directories
if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
if (!(Test-Path $HtmlDir)) { New-Item -ItemType Directory -Path $HtmlDir -Force | Out-Null }

# ===== START LOGGING =====
Start-Transcript -Path $LogFile -Append | Out-Null
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SCAN STARTED: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ===== PATH VALIDATION =====
Write-Host ""
Write-Host "Target folder: $SharePath" -ForegroundColor Cyan
Write-Host "Criteria: older than $DaysOld days AND larger than $MinSizeMB MB" -ForegroundColor Cyan
Write-Host "Cutoff date: $($CutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
Write-Host ""

if (!(Test-Path $SharePath)) {
    Write-Host "ERROR: Path does not exist!" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Read-Host "Press Enter to exit"
    exit
}

# ===== FUNCTIONS =====
function Get-FolderOwner {
    param([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $owner = $acl.Owner
        if ($owner -like "S-1-5-*") {
            $obj = New-Object System.Security.Principal.SecurityIdentifier($owner)
            $owner = $obj.Translate([System.Security.Principal.NTAccount]).Value
        }
        if ($owner -like "*\*") { $owner = $owner.Split("\")[1] }
        return $owner
    } catch {
        return "unknown"
    }
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

# ===== MAIN SCAN (with try/catch for safe interrupt) =====
$usersData = @{}
$summaryReport = @()
$scanStartTime = Get-Date

try {
    $folders = Get-ChildItem -Path $SharePath -Directory -ErrorAction SilentlyContinue
    $rootFiles = Get-ChildItem -Path $SharePath -File -ErrorAction SilentlyContinue

    Write-Host "Found $($folders.Count) subfolders" -ForegroundColor Green
    Write-Host "Found $($rootFiles.Count) files in root" -ForegroundColor Green
    Write-Host ""

    $totalFolders = $folders.Count
    $current = 0

    foreach ($folder in $folders) {
        $current++
        $elapsed = (Get-Date) - $scanStartTime
        $elapsedMin = [math]::Round($elapsed.TotalMinutes, 1)
        
        Write-Progress -Activity "Scanning folders" -Status "$($folder.Name) ($current/$totalFolders) [$elapsedMin min]" -PercentComplete (($current/$totalFolders)*100)
        Write-Host "[$current/$totalFolders] $($folder.Name)" -ForegroundColor Yellow

        $owner = Get-FolderOwner -Path $folder.FullName

        $allFiles = Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue
        $totalSize = ($allFiles | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $totalSize) { $totalSize = 0 }

        $badFiles = $allFiles | Where-Object { 
            $_.LastWriteTime -lt $CutoffDate -and $_.Length -ge ($MinSizeMB * 1MB) 
        }
        $badSize = ($badFiles | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $badSize) { $badSize = 0 }
        $badCount = @($badFiles).Count

        $summaryReport += [PSCustomObject]@{
            Folder      = $folder.Name
            Owner       = $owner
            TotalFiles  = @($allFiles).Count
            TotalSizeGB = [math]::Round($totalSize / 1GB, 2)
            BadFiles    = $badCount
            BadSizeGB   = [math]::Round($badSize / 1GB, 2)
            Path        = $folder.FullName
        }

        if ($badCount -gt 0) {
            if (!$usersData.ContainsKey($owner)) {
                $usersData[$owner] = @{
                    TotalBadSize = 0
                    TotalBadCount = 0
                    Files = @()
                }
            }
            $usersData[$owner].TotalBadSize += $badSize
            $usersData[$owner].TotalBadCount += $badCount
            
            foreach ($f in $badFiles) {
                $usersData[$owner].Files += [PSCustomObject]@{
                    Name = $f.Name
                    SizeMB = [math]::Round($f.Length / 1MB, 2)
                    Date = $f.LastWriteTime.ToString("yyyy-MM-dd")
                    Path = $f.FullName
                    Folder = $folder.Name
                }
            }
        }

        # Intermediate CSV save every 20 folders
        if ($current % 20 -eq 0) {
            $summaryReport | Sort-Object BadSizeGB -Descending | Export-Csv -Path $SummaryCSV -NoTypeInformation -Encoding UTF8
            Write-Host "  [Intermediate save] CSV updated" -ForegroundColor DarkGray
        }
    }

    # Root files
    if ($rootFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "Scanning root files..." -ForegroundColor Yellow
        $rootOwner = Get-FolderOwner -Path $SharePath
        
        $rootTotalSize = ($rootFiles | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $rootTotalSize) { $rootTotalSize = 0 }
        
        $rootBadFiles = $rootFiles | Where-Object { 
            $_.LastWriteTime -lt $CutoffDate -and $_.Length -ge ($MinSizeMB * 1MB) 
        }
        $rootBadSize = ($rootBadFiles | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $rootBadSize) { $rootBadSize = 0 }
        $rootBadCount = @($rootBadFiles).Count
        
        $summaryReport += [PSCustomObject]@{
            Folder      = "[ROOT]"
            Owner       = $rootOwner
            TotalFiles  = @($rootFiles).Count
            TotalSizeGB = [math]::Round($rootTotalSize / 1GB, 2)
            BadFiles    = $rootBadCount
            BadSizeGB   = [math]::Round($rootBadSize / 1GB, 2)
            Path        = $SharePath
        }
        
        if ($rootBadCount -gt 0) {
            if (!$usersData.ContainsKey($rootOwner)) {
                $usersData[$rootOwner] = @{
                    TotalBadSize = 0
                    TotalBadCount = 0
                    Files = @()
                }
            }
            $usersData[$rootOwner].TotalBadSize += $rootBadSize
            $usersData[$rootOwner].TotalBadCount += $rootBadCount
            
            foreach ($f in $rootBadFiles) {
                $usersData[$rootOwner].Files += [PSCustomObject]@{
                    Name = $f.Name
                    SizeMB = [math]::Round($f.Length / 1MB, 2)
                    Date = $f.LastWriteTime.ToString("yyyy-MM-dd")
                    Path = $f.FullName
                    Folder = "[ROOT]"
                }
            }
        }
    }

    Write-Progress -Activity "Scanning folders" -Completed
    Write-Host ""
    Write-Host "Scan completed in $([math]::Round(((Get-Date) - $scanStartTime).TotalMinutes, 1)) minutes" -ForegroundColor Green

} catch {
    Write-Host ""
    Write-Host "ERROR during scan: $_" -ForegroundColor Red
    Write-Host "Partial data will be saved." -ForegroundColor Yellow
}

# ===== CALCULATE TOTALS =====
$totalSize = ($summaryReport | Measure-Object TotalSizeGB -Sum).Sum
$totalBad  = ($summaryReport | Measure-Object BadSizeGB -Sum).Sum
$totalBadFiles = ($summaryReport | Measure-Object BadFiles -Sum).Sum
$badPercent = if ($totalSize -gt 0) { [math]::Round(($totalBad / $totalSize) * 100, 1) } else { 0 }

# ===== SAVE SUMMARY CSV =====
Write-Host ""
Write-Host "Saving Summary CSV..." -ForegroundColor Cyan
$summaryReport | Sort-Object BadSizeGB -Descending | Export-Csv -Path $SummaryCSV -NoTypeInformation -Encoding UTF8
Write-Host "  [OK] $SummaryCSV" -ForegroundColor Green

# ===== SAVE PERSONAL TXT REPORTS =====
Write-Host ""
Write-Host "Generating personal TXT reports..." -ForegroundColor Cyan

foreach ($user in $usersData.Keys) {
    $data = $usersData[$user]
    $totalGB = [math]::Round($data.TotalBadSize / 1GB, 2)
    $count = $data.TotalBadCount
    
    $sortedFiles = $data.Files | Sort-Object SizeMB -Descending
    
    $report = @()
    $report += "============================================================"
    $report += "  OLD AND LARGE FILES REPORT"
    $report += "============================================================"
    $report += ""
    $report += "User: $user"
    $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $report += "Folder: $SharePath"
    $report += "Criteria: older than 2 years AND larger than $MinSizeMB MB"
    $report += ""
    $report += "------------------------------------------------------------"
    $report += "TOTAL: $count files, $totalGB GB"
    $report += "YOU CAN FREE UP: $totalGB GB by deleting these files"
    $report += "------------------------------------------------------------"
    $report += ""
    $report += "FILE LIST (sorted by size):"
    $report += ""
    
    $i = 1
    foreach ($f in $sortedFiles) {
        $report += "$i. $($f.Name)"
        $report += "   Size: $($f.SizeMB) MB"
        $report += "   Date: $($f.Date)"
        $report += "   Folder: $($f.Folder)"
        $report += "   Path: $($f.Path)"
        $report += ""
        $i++
    }
    
    $report += "============================================================"
    $report += "PLEASE REVIEW THESE FILES AND:"
    $report += "  - Delete unnecessary files to free up $totalGB GB"
    $report += "  - Move important files to personal archive"
    $report += "  - Report results to IT department by $Deadline"
    $report += "============================================================"
    
    $fileName = "$user.txt"
    $filePath = Join-Path $OutputDir $fileName
    $report | Out-File -FilePath $filePath -Encoding UTF8
    Write-Host "  [OK] $user - $count files, $totalGB GB (free up $totalGB GB)" -ForegroundColor Green
}

# ===== GENERATE HTML REPORTS =====
Write-Host ""
Write-Host "Generating HTML reports..." -ForegroundColor Cyan

$css = @"
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #f0f2f5; color: #333; margin: 0; padding: 20px; }
  .container { max-width: 1400px; margin: 0 auto; }
  .header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
  .header h1 { margin: 0 0 10px 0; font-size: 28px; }
  .header p { margin: 0; opacity: 0.9; font-size: 14px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 25px; }
  .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); border-left: 4px solid #2a5298; }
  .card.danger { border-left-color: #e74c3c; }
  .card.warning { border-left-color: #f39c12; }
  .card.success { border-left-color: #27ae60; }
  .card-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .card-value { font-size: 28px; font-weight: bold; color: #2c3e50; }
  .card-value.danger { color: #e74c3c; }
  .card-value.warning { color: #f39c12; }
  .section { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); margin-bottom: 25px; }
  .section h2 { margin-top: 0; color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: 600; font-size: 13px; }
  td { padding: 10px 12px; border-bottom: 1px solid #ecf0f1; font-size: 13px; }
  tr:hover { background: #f8f9fa; }
  .bar-cell { width: 150px; }
  .bar-bg { background: #ecf0f1; border-radius: 4px; height: 20px; overflow: hidden; }
  .bar-fill { background: linear-gradient(90deg, #e74c3c, #f39c12); height: 100%; display: flex; align-items: center; justify-content: flex-end; padding-right: 6px; color: white; font-size: 11px; font-weight: bold; min-width: 30px; }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
  .badge-danger { background: #fde8e8; color: #c0392b; }
  .badge-warning { background: #fef5e7; color: #d68910; }
  .badge-ok { background: #e8f8f5; color: #1e8449; }
  .path-cell { font-family: Consolas, monospace; font-size: 11px; color: #7f8c8d; word-break: break-all; }
  .footer { text-align: center; color: #95a5a6; font-size: 12px; margin-top: 30px; padding: 20px; }
  .top-user { display: flex; align-items: center; padding: 12px; background: #f8f9fa; border-radius: 6px; margin-bottom: 8px; }
  .top-user-rank { width: 30px; height: 30px; background: #2a5298; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 15px; }
  .top-user-rank.gold { background: #f1c40f; color: #333; }
  .top-user-rank.silver { background: #bdc3c7; }
  .top-user-rank.bronze { background: #e67e22; }
  .top-user-info { flex-grow: 1; }
  .top-user-name { font-weight: bold; color: #2c3e50; }
  .top-user-size { color: #e74c3c; font-weight: bold; font-size: 16px; }
</style>
"@

# --- Summary HTML ---
$summaryHtml = @"
<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<title>Summary Report</title>
$css
</head><body>
<div class="container">
  <div class="header">
    <h1>Summary Report: Network Disk Analysis</h1>
    <p>Folder: $SharePath</p>
    <p>Date: $(Get-Date -Format "dd.MM.yyyy HH:mm")</p>
    <p>Criteria: files older than $DaysOld days AND larger than $MinSizeMB MB</p>
  </div>

  <div class="cards">
    <div class="card">
      <div class="card-label">Total Folders</div>
      <div class="card-value">$($summaryReport.Count)</div>
    </div>
    <div class="card">
      <div class="card-label">Total Size</div>
      <div class="card-value">$([math]::Round($totalSize, 2)) GB</div>
    </div>
    <div class="card danger">
      <div class="card-label">Old Files Count</div>
      <div class="card-value danger">$totalBadFiles</div>
    </div>
    <div class="card danger">
      <div class="card-label">You Can Free Up</div>
      <div class="card-value danger">$([math]::Round($totalBad, 2)) GB</div>
      <div style="font-size:11px;color:#7f8c8d;margin-top:5px;">by deleting $totalBadFiles old files</div>
    </div>
    <div class="card warning">
      <div class="card-label">Old Files Share</div>
      <div class="card-value warning">$badPercent%</div>
    </div>
  </div>

  <div class="section">
    <h2>Top Users by Old Files</h2>
"@

$userGroups = $summaryReport | Group-Object Owner | ForEach-Object {
    [PSCustomObject]@{
        Owner = $_.Name
        BadFiles = ($_.Group | Measure-Object BadFiles -Sum).Sum
        BadSizeGB = [math]::Round(($_.Group | Measure-Object BadSizeGB -Sum).Sum, 2)
    }
} | Sort-Object BadSizeGB -Descending | Where-Object { $_.BadSizeGB -gt 0 }

if ($userGroups.Count -gt 0) {
    $maxBadSize = $userGroups[0].BadSizeGB
    $rank = 1
    foreach ($u in $userGroups) {
        $rankClass = ""
        if ($rank -eq 1) { $rankClass = "gold" }
        elseif ($rank -eq 2) { $rankClass = "silver" }
        elseif ($rank -eq 3) { $rankClass = "bronze" }
        
        $barWidth = [math]::Round(($u.BadSizeGB / $maxBadSize) * 100, 0)
        
        $summaryHtml += @"
    <div class="top-user">
      <div class="top-user-rank $rankClass">$rank</div>
      <div class="top-user-info">
        <div class="top-user-name">$($u.Owner)</div>
        <div style="font-size:12px;color:#7f8c8d;">$($u.BadFiles) files</div>
      </div>
      <div style="flex-grow:1;margin:0 15px;">
        <div class="bar-bg"><div class="bar-fill" style="width:$barWidth%">$barWidth%</div></div>
      </div>
      <div class="top-user-size">$($u.BadSizeGB) GB</div>
    </div>
"@
        $rank++
    }
} else {
    $summaryHtml += "<p>No users with old files found.</p>"
}

$summaryHtml += @"
  </div>

  <div class="section">
    <h2>Folder Details</h2>
    <table>
      <thead>
        <tr>
          <th>Folder</th>
          <th>Owner</th>
          <th>Total Files</th>
          <th>Total Size</th>
          <th>Old Files</th>
          <th>Old Size</th>
          <th>Share</th>
          <th>Visual</th>
        </tr>
      </thead>
      <tbody>
"@

foreach ($row in ($summaryReport | Sort-Object BadSizeGB -Descending)) {
    $folderBadPercent = if ($row.TotalSizeGB -gt 0) { [math]::Round(($row.BadSizeGB / $row.TotalSizeGB) * 100, 1) } else { 0 }
    $badgeClass = "badge-ok"
    if ($folderBadPercent -gt 50) { $badgeClass = "badge-danger" }
    elseif ($folderBadPercent -gt 20) { $badgeClass = "badge-warning" }
    
    $barWidth = [math]::Min($folderBadPercent, 100)
    
    $summaryHtml += @"
        <tr>
          <td><b>$($row.Folder)</b></td>
          <td>$($row.Owner)</td>
          <td>$($row.TotalFiles)</td>
          <td>$($row.TotalSizeGB) GB</td>
          <td>$($row.BadFiles)</td>
          <td><b>$($row.BadSizeGB) GB</b></td>
          <td><span class="badge $badgeClass">$folderBadPercent%</span></td>
          <td class="bar-cell"><div class="bar-bg"><div class="bar-fill" style="width:$barWidth%">$folderBadPercent%</div></div></td>
        </tr>
"@
}

$summaryHtml += @"
      </tbody>
    </table>
  </div>

  <div class="footer">
    Auto-generated report | IT Department | $(Get-Date -Format "dd.MM.yyyy")
  </div>
</div>
</body></html>
"@

$summaryHtmlPath = Join-Path $HtmlDir "SUMMARY_REPORT.html"
$summaryHtml | Out-File -FilePath $summaryHtmlPath -Encoding UTF8
Write-Host "  [OK] Summary HTML: $summaryHtmlPath" -ForegroundColor Green

# --- Personal HTML reports ---
foreach ($user in $usersData.Keys) {
    $data = $usersData[$user]
    $totalGB = [math]::Round($data.TotalBadSize / 1GB, 2)
    $count = $data.TotalBadCount
    
    $sortedFiles = $data.Files | Sort-Object SizeMB -Descending
    
    $personalHtml = @"
<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<title>Report for $user</title>
$css
</head><body>
<div class="container">
  <div class="header">
    <h1>File Review Notification</h1>
    <p>User: <b>$user</b> | Date: $(Get-Date -Format "dd.MM.yyyy HH:mm")</p>
    <p>Folder: $SharePath</p>
  </div>

  <div class="cards">
    <div class="card danger">
      <div class="card-label">Old Files Found</div>
      <div class="card-value danger">$count</div>
    </div>
    <div class="card danger">
      <div class="card-label">You Can Free Up</div>
      <div class="card-value danger">$totalGB GB</div>
      <div style="font-size:11px;color:#7f8c8d;margin-top:5px;">by deleting $count old files</div>
    </div>
    <div class="card warning">
      <div class="card-label">Deadline</div>
      <div class="card-value warning" style="font-size:22px;">$Deadline</div>
    </div>
  </div>

  <div class="section">
    <h2>Files Requiring Review</h2>
    <p style="color:#7f8c8d;font-size:13px;">Criteria: older than 2 years AND larger than $MinSizeMB MB. Sorted by size (descending).</p>
    <table>
      <thead>
        <tr>
          <th style="width:40px;">#</th>
          <th>File Name</th>
          <th style="width:100px;">Size</th>
          <th style="width:110px;">Date</th>
          <th style="width:150px;">Folder</th>
          <th>Full Path</th>
        </tr>
      </thead>
      <tbody>
"@
    
    $idx = 1
    foreach ($f in $sortedFiles) {
        $personalHtml += @"
        <tr>
          <td><b>$idx</b></td>
          <td><b>$($f.Name)</b></td>
          <td><span class="badge badge-danger">$($f.SizeMB) MB</span></td>
          <td>$($f.Date)</td>
          <td>$($f.Folder)</td>
          <td class="path-cell">$($f.Path)</td>
        </tr>
"@
        $idx++
    }
    
    $personalHtml += @"
      </tbody>
    </table>
  </div>

  <div class="section" style="background:#fff8e1;border-left:4px solid #f39c12;">
    <h2 style="color:#d68910;">Required Actions</h2>
    <ol style="font-size:14px;line-height:1.8;">
      <li>Review the file list above</li>
      <li><b>Delete</b> unnecessary files to free up <b>$totalGB GB</b></li>
      <li><b>Move</b> important files to personal archive</li>
      <li>Reply with results by <b>$Deadline</b></li>
    </ol>
    <p style="margin-top:15px;padding:10px;background:#e8f8f5;border-radius:4px;font-size:13px;color:#1e8449;">
      By cleaning up these $count files, you will free up <b>$totalGB GB</b> of disk space.
    </p>
    <p style="margin-top:15px;font-size:13px;color:#7f8c8d;">
      If all files are important and cannot be deleted, please inform us. We will consider moving them to archive storage.
    </p>
  </div>

  <div class="footer">
    IT Department | $(Get-Date -Format "dd.MM.yyyy")
  </div>
</div>
</body></html>
"@
    
    $outPath = Join-Path $HtmlDir "$user.html"
    $personalHtml | Out-File -FilePath $outPath -Encoding UTF8
    Write-Host "  [OK] Personal HTML: $user ($count files, $totalGB GB)" -ForegroundColor Green
}

# ===== FINAL STATS =====
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "  Folder: $SharePath" -ForegroundColor White
Write-Host "  Total size: $([math]::Round($totalSize, 2)) GB" -ForegroundColor White
Write-Host "  Old+big files: $totalBadFiles files" -ForegroundColor Yellow
Write-Host "  Space you can free up: $([math]::Round($totalBad, 2)) GB" -ForegroundColor Green
Write-Host "  Old files share: $badPercent%" -ForegroundColor Yellow
Write-Host "  Users with old files: $($usersData.Count)" -ForegroundColor White
Write-Host "  Duration: $([math]::Round(((Get-Date) - $scanStartTime).TotalMinutes, 1)) minutes" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Reports saved to:" -ForegroundColor Green
Write-Host "  CSV:  $SummaryCSV" -ForegroundColor White
Write-Host "  TXT:  $OutputDir" -ForegroundColor White
Write-Host "  HTML: $HtmlDir" -ForegroundColor White
Write-Host "  LOG:  $LogFile" -ForegroundColor White
Write-Host ""

Stop-Transcript | Out-Null
Read-Host "Press Enter to exit"
