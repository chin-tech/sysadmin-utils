function New-LockScreen {


   Add-Type -AssemblyName System.Drawing

   $templatePath = "C:\Supportbin\lockscreen_template.jpg"
   $outputPath   = "C:\ProgramData\LockScreen\lockscreen.jpg"

   # Ensure output directory exists
   $outputDir = [System.IO.Path]::GetDirectoryName($outputPath)
   if (-not (Test-Path $outputDir)) {
      New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
   }

   # Load base image into memory to avoid file locks
   $bytes = [System.IO.File]::ReadAllBytes($templatePath)
   $ms    = [System.IO.MemoryStream]::new($bytes)
   $bmp   = [System.Drawing.Bitmap]::FromStream($ms)
   $gfx   = [System.Drawing.Graphics]::FromImage($bmp)

   # Render quality settings
   $gfx.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
   $gfx.TextRenderingHint  = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

   # Prepare text & font
   $hostName = $env:COMPUTERNAME
   $font     = [System.Drawing.Font]::new("Segoe UI", 28, [System.Drawing.FontStyle]::Bold)
   $brush    = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
   $shadow   = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(180, 0, 0, 0))

   # Position (e.g., top-right corner with margin)
   $textSize = $gfx.MeasureString($hostName, $font)
   $x = $bmp.Width - $textSize.Width - 60
   $y = 50

   # Draw drop shadow, then text
   $gfx.DrawString($hostName, $font, $shadow, ($x + 2), ($y + 2))
   $gfx.DrawString($hostName, $font, $brush, $x, $y)

   # Save result as JPEG
   $bmp.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Jpeg)

   # Clean up resources
   $gfx.Dispose()
   $bmp.Dispose()
   $ms.Dispose()
}

### Create user profiles of hostname:
Add-Type -AssemblyName System.Drawing

function New-DefaultUserAvatars {
   [CmdletBinding()]
   param(
      [Parameter(Mandatory=$false)]
      [string]$AvatarText = $env:COMPUTERNAME,
        
      [Parameter(Mandatory=$false)]
      [string]$TargetFolder = "$env:ProgramData\Microsoft\User Account Pictures"
   )

   $resolutions = @(
      @{ File = "user-32.png";  Size = 32;  Format = [System.Drawing.Imaging.ImageFormat]::Png; Transparent = $true }
      @{ File = "user-40.png";  Size = 40;  Format = [System.Drawing.Imaging.ImageFormat]::Png; Transparent = $true }
      @{ File = "user-48.png";  Size = 48;  Format = [System.Drawing.Imaging.ImageFormat]::Png; Transparent = $true }
      @{ File = "user-192.png"; Size = 192; Format = [System.Drawing.Imaging.ImageFormat]::Png; Transparent = $true }
      @{ File = "user.png";     Size = 448; Format = [System.Drawing.Imaging.ImageFormat]::Png; Transparent = $true }
      @{ File = "user.bmp";     Size = 128; Format = [System.Drawing.Imaging.ImageFormat]::Bmp; Transparent = $false }
   )

   if (-not (Test-Path $TargetFolder)) {
      New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null
   }

   try {
      & takeown.exe /F "$TargetFolder\user*" /A 2>$null | Out-Null
      & icacls.exe "$TargetFolder\user*" /grant "Administrators:F" 2>$null | Out-Null
   } catch {
   }

   foreach ($res in $resolutions) {
      $size = $res.Size
      $outPath = Join-Path $TargetFolder $res.File

      $bmp = [System.Drawing.Bitmap]::new($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
      $gfx = [System.Drawing.Graphics]::FromImage($bmp)

      $gfx.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
      $gfx.TextRenderingHint  = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
      $gfx.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $gfx.PixelOffsetMode    = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

      if ($res.Transparent) {
         $gfx.Clear([System.Drawing.Color]::FromArgb(0, 0, 0, 0))
      } else {
         $gfx.Clear([System.Drawing.Color]::FromArgb(32, 32, 32))
      }

      # Text selection: For tiny sizes (<= 48px), if the text is longer than 5 chars,
      # abbreviate to 3-4 chars to keep it from degrading into an unreadable pixel blur.
      $renderText = $AvatarText
      if ($size -le 48 -and $AvatarText.Length -gt 5) {
         $renderText = $AvatarText.Substring(0, [Math]::Min(4, $AvatarText.Length))
      }

      # Use GenericTypographic format to remove GDI+ string padding margins
      $format = [System.Drawing.StringFormat]::new([System.Drawing.StringFormat]::GenericTypographic)
      $format.Alignment     = [System.Drawing.StringAlignment]::Center
      $format.LineAlignment = [System.Drawing.StringAlignment]::Center
      $format.FormatFlags   = [System.Drawing.StringFormatFlags]::NoWrap

      # Windows circular cutout boundary: keep within 70% of total diameter
      $maxAllowedWidth  = $size * 0.70
      $maxAllowedHeight = $size * 0.45

      # Measure & shrink iteratively until bounds are strictly respected
      $fontSize = [Math]::Max(6, [int]($size * 0.40))
      $font = $null

      while ($fontSize -gt 5) {
         if ($font) { $font.Dispose() 
         }
         $font = [System.Drawing.Font]::new("Segoe UI", $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
            
         $measured = $gfx.MeasureString($renderText, $font, [System.Drawing.PointF]::new(0,0), $format)
         if ($measured.Width -le $maxAllowedWidth -and $measured.Height -le $maxAllowedHeight) {
            break
         }
         $fontSize--
      }

      $brush  = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
      $shadow = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(180, 0, 0, 0))

      $rect = [System.Drawing.RectangleF]::new(0, 0, $size, $size)
        
      # Micro drop-shadow (1px for small, 2px for large)
      $offset = if ($size -ge 128) { 2.0 
      } else { 1.0 
      }
      $shadowRect = [System.Drawing.RectangleF]::new($offset, $offset, $size, $size)

      $gfx.DrawString($renderText, $font, $shadow, $shadowRect, $format)
      $gfx.DrawString($renderText, $font, $brush, $rect, $format)

      try {
         $bmp.Save($outPath, $res.Format)
         Write-Verbose "Rendered: $outPath ($($size)x$($size)) text='$renderText' at ${fontSize}px"
      } catch {
         Write-Warning "Failed writing $outPath: $($_.Exception.Message)"
      }

      # Cleanup
      $brush.Dispose()
      $shadow.Dispose()
      if ($font) { $font.Dispose() 
      }
      $format.Dispose()
      $gfx.Dispose()
      $bmp.Dispose()
   }
}


