<#
.SYNOPSIS
    يقوم بضغط ملفات المشروع في أرشيف ZIP مطابق تماماً للملفات المرفوعة إلى GitHub مع استثناء جميع الملفات المستثناة بواسطة .gitignore.
    Compresses project files into a clean ZIP archive matching what is pushed to GitHub, strictly excluding .gitignore files.

.DESCRIPTION
    يدعم هذا الاسكربت وضعين:
    1. WorkingTree (الافتراضي): يضغط جميع ملفات المشروع الحالية (بما في ذلك التعديلات غير المحفوظة والملفات الجديدة غير المستثناة) وفق قواعد .gitignore.
    2. Head: يضغط آخر Commit نظيف معتمد على Git باستخدام git archive HEAD.

.PARAMETER OutputPath
    مسار ملف الأرشيف الناتج (اختياري). افتراضياً ينشئ أرشيفاً مؤرخاً في مجلد المشروع.

.PARAMETER Mode
    الوضع المطلوب: Interactive (تفاعلي), WorkingTree (شجرة العمل الحالية), Head (آخر Commit).

.PARAMETER OpenFolder
    فتح مجلد الملف الناتج في مستكشف Windows بعد الانتهاء.

.PARAMETER Quiet
    تشغيل صامت بدون إخراج تفاعلي.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('Interactive', 'WorkingTree', 'Head')]
    [string]$Mode = 'Interactive',

    [Parameter()]
    [switch]$OpenFolder,

    [Parameter()]
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-ColorHost {
    param(
        [string]$Message,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White
    )
    if (-not $Quiet) {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}

try {
    # 1. التحقق من وجود Git
    $gitCheck = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCheck) {
        throw "لم يتم العثور على Git في النظام! يرجى تثبيت Git أو إضافته إلى متغيرات PATH."
    }

    # 2. تحديد المسار الجذري للمستودع
    $repoRoot = git rev-parse --show-toplevel 2>$null
    if (-not $repoRoot -or $LASTEXITCODE -ne 0) {
        throw "المجلد الحالي ليس مستودع Git صالحاً! (Current directory is not a Git repository)"
    }
    $repoRoot = [System.IO.Path]::GetFullPath($repoRoot.Trim().Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    $repoName = [System.IO.Path]::GetFileName($repoRoot)

    Write-ColorHost "============================================================" -ForegroundColor Cyan
    Write-ColorHost "      أداة ضغط وتصدير ملفات المشروع النظيفة لـ GitHub       " -ForegroundColor Yellow
    Write-ColorHost "============================================================" -ForegroundColor Cyan
    Write-ColorHost "[+] مسار المشروع: $repoRoot" -ForegroundColor Gray

    # 3. القائمة التفاعلية في حال كان الوضع Interactive
    $selectedMode = $Mode
    if ($selectedMode -eq 'Interactive') {
        Write-ColorHost ""
        Write-ColorHost "اختر نوع الأرشيف المطلوب:" -ForegroundColor White
        Write-ColorHost "  [1] ملفات العمل الحالية (Working Tree) [الافتراضي]" -ForegroundColor Green
        Write-ColorHost "      - يضغط كل الملفات غير المستثناة بـ .gitignore مع حفظ تعديلاتك الحالية." -ForegroundColor Gray
        Write-ColorHost "  [2] آخر نسخة معتمدة من Git (HEAD Commit)" -ForegroundColor Yellow
        Write-ColorHost "      - نسخة نظيفة 100% مطابقة لآخر رفع تم اعتماده على GitHub." -ForegroundColor Gray
        Write-ColorHost "  [3] إلغاء الأمر والخروج" -ForegroundColor Red
        Write-ColorHost "------------------------------------------------------------" -ForegroundColor DarkGray
        
        $choice = Read-Host "أدخل رقم الخيار [1 أو 2 أو 3] (الافتراضي 1)"
        if ($choice -eq '3') {
            Write-ColorHost "[!] تم إلغاء العملية بناءً على طلبك." -ForegroundColor Yellow
            return
        } elseif ($choice -eq '2') {
            $selectedMode = 'Head'
        } else {
            $selectedMode = 'WorkingTree'
        }
    }

    # 4. تحديد اسم ومسار ملف الأرشيف الناتج
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $archiveName = "${repoName}_GitHub_${selectedMode}_${timestamp}.zip"
        $targetZipPath = Join-Path $repoRoot $archiveName
    } else {
        $targetZipPath = [System.IO.Path]::GetFullPath($OutputPath)
        $parentDir = [System.IO.Path]::GetDirectoryName($targetZipPath)
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
    }

    Write-ColorHost "[+] وضع التصدير: $selectedMode" -ForegroundColor Gray
    Write-ColorHost "[+] ملف الأرشيف : $targetZipPath" -ForegroundColor Gray
    Write-ColorHost "------------------------------------------------------------" -ForegroundColor DarkGray

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $totalRawBytes = 0
    $archivedFilesCount = 0

    if ($selectedMode -eq 'Head') {
        Write-ColorHost "[*] جاري استخراج آخر نسخة معتمدة من Git (git archive HEAD)..." -ForegroundColor Cyan
        
        Push-Location $repoRoot
        try {
            git archive --format=zip -o "$targetZipPath" HEAD
            if ($LASTEXITCODE -ne 0) {
                throw "فشل أمر git archive برمز الخطأ: $LASTEXITCODE"
            }
        } finally {
            Pop-Location
        }

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipReader = [System.IO.Compression.ZipFile]::OpenRead($targetZipPath)
        try {
            $archivedFilesCount = $zipReader.Entries.Count
            foreach ($entry in $zipReader.Entries) {
                $totalRawBytes += $entry.Length
            }
        } finally {
            $zipReader.Dispose()
        }

    } else {
        Write-ColorHost "[*] جاري فحص ملفات المشروع واستبعاد كافة المستثنيات في .gitignore..." -ForegroundColor Cyan
        
        Push-Location $repoRoot
        try {
            $filesList = git ls-files -c -o --exclude-standard
        } finally {
            Pop-Location
        }

        if (-not $filesList -or $filesList.Count -eq 0) {
            throw "لم يتم العثور على أي ملفات صالحة للضغط!"
        }

        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        if (Test-Path $targetZipPath) {
            Remove-Item $targetZipPath -Force
        }

        $zipStream = [System.IO.File]::Open($targetZipPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite)
        $zipArchive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)

        try {
            foreach ($relPath in $filesList) {
                if ([string]::IsNullOrWhiteSpace($relPath)) { continue }

                $fullPath = Join-Path $repoRoot $relPath
                
                # تجنب ضغط ملف الأرشيف نفسه إذا كان داخل المستودع
                if ([System.IO.Path]::GetFullPath($fullPath) -eq $targetZipPath) {
                    continue
                }

                if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                    $entryName = $relPath.Replace('\', '/')
                    $fileInfo = New-Object System.IO.FileInfo($fullPath)
                    $totalRawBytes += $fileInfo.Length

                    $entry = $zipArchive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
                    $entryStream = $entry.Open()
                    $fs = [System.IO.File]::OpenRead($fullPath)
                    try {
                        $fs.CopyTo($entryStream)
                    } finally {
                        $fs.Dispose()
                        $entryStream.Dispose()
                    }
                    $archivedFilesCount++
                }
            }
        } finally {
            $zipArchive.Dispose()
            $zipStream.Dispose()
        }
    }

    $sw.Stop()
    $zipSize = (Get-Item -LiteralPath $targetZipPath).Length
    $rawMb = [math]::Round($totalRawBytes / 1MB, 2)
    $zipMb = [math]::Round($zipSize / 1MB, 2)
    $ratio = if ($totalRawBytes -gt 0) { [math]::Round((1 - ($zipSize / $totalRawBytes)) * 100, 1) } else { 0 }

    Write-ColorHost "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-ColorHost "[✔] تم إنشاء الأرشيف بنجاح!" -ForegroundColor Green
    Write-ColorHost "    • عدد الملفات المضمنة   : $archivedFilesCount ملف" -ForegroundColor White
    Write-ColorHost "    • الحجم الأصلي          : $rawMb MB" -ForegroundColor White
    Write-ColorHost "    • الحجم بعد الضغط       : $zipMb MB (نسبة تقليص: $ratio%)" -ForegroundColor White
    Write-ColorHost "    • الوقت المستغرق        : $($sw.Elapsed.TotalSeconds.ToString('F2')) ثانية" -ForegroundColor White
    Write-ColorHost "    • مسار الملف المضغوط    : $targetZipPath" -ForegroundColor Yellow
    Write-ColorHost "============================================================" -ForegroundColor Cyan

    # فتح المجلد إذا طُلب أو في الوضع التفاعلي
    $shouldOpen = $OpenFolder.IsPresent
    if (-not $shouldOpen -and $Mode -eq 'Interactive') {
        Write-ColorHost ""
        $openChoice = Read-Host "هل تريد فتح المجلد الذي يحتوي على الملف المضغوط؟ (Y/N) [الافتراضي: Y]"
        if ([string]::IsNullOrWhiteSpace($openChoice) -or $openChoice.Trim().ToUpper() -eq 'Y') {
            $shouldOpen = $true
        }
    }

    if ($shouldOpen) {
        Write-ColorHost "[*] جاري فتح المجلد في مستكشف Windows..." -ForegroundColor Cyan
        Start-Process explorer.exe -ArgumentList "/select,`"$targetZipPath`""
    }

    return [PSCustomObject]@{
        Success           = $true
        ArchiveFile       = $targetZipPath
        FilesCount        = $archivedFilesCount
        RawSizeMB         = $rawMb
        CompressedSizeMB  = $zipMb
        ElapsedSeconds    = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    }

} catch {
    Write-ColorHost "[✖] خطأ أثناء عملية الضغط: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
