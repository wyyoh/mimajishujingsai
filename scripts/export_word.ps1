param([Parameter(Mandatory=$true)][string]$InputPath,[Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
$word=$null
$doc=$null
try {
  $word=New-Object -ComObject Word.Application
  $word.Visible=$false
  $word.DisplayAlerts=0
  $word.AutomationSecurity=3
  $doc=$word.Documents.Open([IO.Path]::GetFullPath($InputPath),$false,$true,$false)
  $doc.ExportAsFixedFormat([IO.Path]::GetFullPath($OutputPath),17)
  Write-Output ('Word PDF export '+$word.Version)
} finally {
  if ($null -ne $doc) { $doc.Close(0); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($doc) }
  if ($null -ne $word) { $word.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word) }
}
