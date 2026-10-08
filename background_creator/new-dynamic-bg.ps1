Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# ---------------------------------------------------------
# 1. Gather Metadata & System Information
# ---------------------------------------------------------
$hostname   = $env:COMPUTERNAME
$uptimeDays = ((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).Days
$domain     = (Get-CimInstance Win32_ComputerSystem).Domain
$osCaption  = (Get-CimInstance Win32_OperatingSystem).Caption
$osBuild    = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$serialNum  = (Get-CimInstance Win32_BIOS).SerialNumber

# Active IPv4 addresses (excluding loopback and APIPA)
$ipList = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Ethernet*','Wi-Fi*' -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notmatch '^(169\.254\.|127\.)' }).IPAddress -join ' | '
if (-not $ipList) { $ipList = "Disconnected / No IP" }

# ---------------------------------------------------------
# 2. Define Key-Value Records (Ordered for Alignment)
# ---------------------------------------------------------
$PocTitle = "SA - Point of contacts - Submit a Ticket: WEBSITE"
$SysInfoTitle = "System Information"
$pocData = [ordered]@{
   "Primary"  = "Milo Santiago - msantiago@domain.local"
   "Tech-1" = "Alo Nolan - anolan@domain.local"
   "Tech-2"   = "Mac Daddy - mdaddy@domain.local"
   "Tech-3"   = "Dj Khaleed - dkhaleed@domain.local"
   "Tech-4"   = "Last Person - lperson@domain.local"
}

$sysData = [ordered]@{
   "Host | Domain"  = "$hostname | $domain"
   "Serial Number"  = $serialNum
   "IPv4 Address"   = $ipList
   "Operating Sys"  = "$osCaption (Build $osBuild)"
   "System Uptime"  = "$uptimeDays days"
}

# ---------------------------------------------------------
# 3. Canvas & Geometry Setup
# ---------------------------------------------------------
# Match primary display or default to 1920x1080
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$width  = $bounds.Width
$height = $bounds.Height

$bitmap   = New-Object System.Drawing.Bitmap $width, $height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
$graphics.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Dark base canvas background
$bgBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(18, 22, 28))
$graphics.FillRectangle($bgBrush, 0, 0, $width, $height)

# Fonts & Palette
$fontFamily = New-Object System.Drawing.FontFamily "Consolas"
$headerFont = New-Object System.Drawing.Font ($fontFamily, 14, [System.Drawing.FontStyle]::Bold)
$lineFont   = New-Object System.Drawing.Font ($fontFamily, 12, [System.Drawing.FontStyle]::Regular)

$headerBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(86, 156, 214))  # Muted Blue
$keyBrush    = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(156, 220, 254))  # Light Blue
$valBrush    = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(212, 212, 212))  # Crisp Gray
$cardBrush   = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(28, 34, 44))    # Elevated card
$cardBorder  = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(50, 60, 75), 1.5)

# ---------------------------------------------------------
# 4. Measure Longest Strings for Precise Centering
# ---------------------------------------------------------
# Determine max width of keys and values to ensure tab stops stay aligned
$maxKeyWidth = 0.0
$maxValWidth = 0.0

foreach ($map in @($pocData, $sysData)) {
   foreach ($entry in $map.GetEnumerator()) {
      $kSize = $graphics.MeasureString($entry.Key + " :", $lineFont)
      $vSize = $graphics.MeasureString($entry.Value, $lineFont)
      if ($kSize.Width -gt $maxKeyWidth) { $maxKeyWidth = $kSize.Width }
      if ($vSize.Width -gt $maxValWidth) { $maxValWidth = $vSize.Width }
   }
}

$blockContentWidth = [Math]::Ceiling($maxKeyWidth + 15 + $maxValWidth)
$lineHeight        = 24
$sectionSpacing    = 20
$paddingX          = 45
$paddingY          = 35

# Calculate total box height
$totalLines  = 2 + $pocData.Count + $sysData.Count # 2 headers + item counts
$blockHeight = ($totalLines * $lineHeight) + ($sectionSpacing * 2)

$boxWidth  = $blockContentWidth + ($paddingX * 2)
$boxHeight = $blockHeight + ($paddingY * 2)

# Centered coordinates on screen
$boxX = [Math]::Round(($width - $boxWidth) / 2)
$boxY = [Math]::Round(($height - $boxHeight) / 2)

# ---------------------------------------------------------
# 5. Render Centered Card & Text
# ---------------------------------------------------------
# Draw background card
$graphics.FillRectangle($cardBrush, $boxX, $boxY, $boxWidth, $boxHeight)
$graphics.DrawRectangle($cardBorder, $boxX, $boxY, $boxWidth, $boxHeight)

$currentX = $boxX + $paddingX
$currentY = $boxY + $paddingY
$valueX   = $currentX + $maxKeyWidth + 15

# Helper: Draw section block
function Draw-SectionBlock ($title, [System.Collections.IDictionary]$dict) {
   # Section Header
   $graphics.DrawString($title.ToUpper(), $headerFont, $headerBrush, $currentX, $script:currentY)
   $script:currentY += $lineHeight + 6

   # Key-Value pairs
   foreach ($item in $dict.GetEnumerator()) {
      $keyText = ($item.Key + " :")
      $graphics.DrawString($keyText, $lineFont, $keyBrush, $currentX, $script:currentY)
      $graphics.DrawString($item.Value, $lineFont, $valBrush, $valueX, $script:currentY)
      $script:currentY += $lineHeight
   }
   $script:currentY += $sectionSpacing
}

Draw-SectionBlock -title "$PocTitle" -dict $pocData
Draw-SectionBlock -title "$SysInfoTitle" -dict $sysData

# ---------------------------------------------------------
# 6. Save & Commit Wallpaper
# ---------------------------------------------------------
$destDir = "$env:LOCALAPPDATA\SystemWallpaper"
if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
$destPath = "$destDir\wallpaper.bmp"

$bitmap.Save($destPath, [System.Drawing.Imaging.ImageFormat]::Bmp)

$graphics.Dispose()
$bitmap.Dispose()

# Update Active Desktop
$code = @'
using System.Runtime.InteropServices;
public class Desktop {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
[Desktop]::SystemParametersInfo(0x0014, 0, $destPath, 0x01 -bor 0x02) | Out-Null
