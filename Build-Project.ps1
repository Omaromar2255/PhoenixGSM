<#
.SYNOPSIS
    اسكربت بناء مشروع PhoenixGSM الموحد ومراقبة الأجهزة
    Builds the PhoenixGSM Toolkit into the external output directory (PhoenixGSMtools)

.DESCRIPTION
    يقوم ببناء المشروع ومخرجاته بالكامل في المسار الخارجي:
    C:\Users\pc5\Documents\GitHub\PhoenixGSMtools\<Configuration>\net8.0-windows\
    ليبقى مجلد المشروع نظيفاً وصغيراً وخالياً من ملفات وسجلات التشغيل الضخمة.

.PARAMETER Configuration
    نوع البناء: Debug (افتراضي) أو Release

.PARAMETER Clean
    تنظيف مجلد المخرجات قبل البناء وإعادة تجميع الملفات

.PARAMETER Run
    تشغيل واجهة المراقبة (MonitoringStudio) تلقائياً فور انتهاء البناء بنجاح

.PARAMETER Mode
    الوضع المطلوب: Interactive (تفاعلي), BuildDebug, BuildRelease, Rebuild, BuildAndRun
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [Parameter()]
    [switch]$Clean,

    [Parameter()]
    [switch]$Run,

    [Parameter()]
    [ValidateSet('Interactive', 'BuildDebug', 'BuildRelease', 'Rebuild', 'BuildAndRun')]
    [string]$Mode = 'Interactive'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-ColorHost {
    param(
        [string]$Message,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White
    )
    Write-Host $Message -ForegroundColor $ForegroundColor
}

try {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $projectPath = Join-Path $scriptDir "tools\MonitoringToolkit\MonitoringStudio\MonitoringStudio.csproj"
    $baseTargetRoot = "C:\Users\pc5\Documents\GitHub\PhoenixGSMtools"

    Write-ColorHost "============================================================" -ForegroundColor Cyan
    Write-ColorHost "      أداة البناء المؤتمتة لمشروع PhoenixGSM Toolkit         " -ForegroundColor Yellow
    Write-ColorHost "============================================================" -ForegroundColor Cyan
    Write-ColorHost "[+] مسار المشروع المستهدف: $projectPath" -ForegroundColor Gray
    Write-ColorHost "[+] مجلد المخرجات الخارجي: $baseTargetRoot" -ForegroundColor Gray

    # 1. التحقق من وجود dotnet SDK
    $dotnetCheck = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnetCheck) {
        throw "لم يتم العثور على مثبت .NET SDK في النظام! يرجى تثبيت .NET 8 SDK."
    }

    if (-not (Test-Path $projectPath)) {
        throw "تعذر العثور على ملف المشروع في: $projectPath"
    }

    # 2. القائمة التفاعلية في حال تشغيل الاسكربت بدون وسطاء
    $selectedConfig = $Configuration
    $doClean = $Clean.IsPresent
    $doRun = $Run.IsPresent

    if ($Mode -eq 'Interactive') {
        Write-ColorHost ""
        Write-ColorHost "اختر العملية المطلوبة:" -ForegroundColor White
        Write-ColorHost "  [1] بناء سريع لوضع التطوير (Debug) [الافتراضي]" -ForegroundColor Green
        Write-ColorHost "  [2] بناء سريع وتشغيل الواجهة فوراً (Build and Run)" -ForegroundColor Cyan
        Write-ColorHost "  [3] إعادة بناء نظيفة بالكامل (Clean and Rebuild Debug)" -ForegroundColor Yellow
        Write-ColorHost "  [4] بناء وضع الإنتاج الكامل (Release)" -ForegroundColor Magenta
        Write-ColorHost "  [5] فتح مجلد المخرجات (PhoenixGSMtools)" -ForegroundColor Gray
        Write-ColorHost "  [6] إلغاء الأمر والخروج" -ForegroundColor Red
        Write-ColorHost "------------------------------------------------------------" -ForegroundColor DarkGray

        $choice = Read-Host "أدخل رقم الخيار [1 إلى 6] (الافتراضي 1)"
        switch ($choice) {
            '2' {
                $selectedConfig = 'Debug'
                $doRun = $true
            }
            '3' {
                $selectedConfig = 'Debug'
                $doClean = $true
            }
            '4' {
                $selectedConfig = 'Release'
            }
            '5' {
                if (-not (Test-Path $baseTargetRoot)) {
                    New-Item -ItemType Directory -Force -Path $baseTargetRoot | Out-Null
                }
                Invoke-Item $baseTargetRoot
                return
            }
            '6' {
                Write-ColorHost "[!] تم إلغاء العملية." -ForegroundColor Yellow
                return
            }
            default {
                $selectedConfig = 'Debug'
            }
        }
    } elseif ($Mode -eq 'BuildAndRun') {
        $selectedConfig = 'Debug'
        $doRun = $true
    } elseif ($Mode -eq 'BuildRelease') {
        $selectedConfig = 'Release'
    } elseif ($Mode -eq 'Rebuild') {
        $selectedConfig = 'Debug'
        $doClean = $true
    }

    $outDir = Join-Path $baseTargetRoot "$selectedConfig\net8.0-windows"
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }

    # 3. خيار التنظيف إذا تم اختياره
    if ($doClean) {
        Write-ColorHost "[*] جاري تنظيف مجلد البناء السابق ($selectedConfig)..." -ForegroundColor Yellow
        dotnet clean $projectPath -c $selectedConfig -v quiet | Out-Null
    }

    # 4. بدء البناء
    Write-ColorHost "[*] جاري بناء المشروع في وضع ($selectedConfig)..." -ForegroundColor Cyan
    $buildStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $buildArgs = @("build", $projectPath, "-c", $selectedConfig, "--no-restore")
    $process = Start-Process -FilePath "dotnet" -ArgumentList $buildArgs -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        # محاولة البناء مع restore في حال كان هناك نقص في الحزم
        Write-ColorHost "[!] إعادة المحاولة مع استعادة الحزم (Restoring packages)..." -ForegroundColor Yellow
        $buildArgsFallback = @("build", $projectPath, "-c", $selectedConfig)
        $process = Start-Process -FilePath "dotnet" -ArgumentList $buildArgsFallback -NoNewWindow -Wait -PassThru
    }

    $buildStopwatch.Stop()

    if ($process.ExitCode -ne 0) {
        throw "فشلت عملية البناء برمز خطأ: $($process.ExitCode)"
    }

    # 5. تنظيف أي مجلد bin قديم متخلف داخل المستودع لضمان نظافته
    $localBinPath = Join-Path $scriptDir "tools\MonitoringToolkit\MonitoringStudio\bin"
    if (Test-Path $localBinPath) {
        Remove-Item -Path $localBinPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 6. فحص الملفات التنفيذية الناتجة
    Write-ColorHost ""
    Write-ColorHost "============================================================" -ForegroundColor Green
    Write-ColorHost "         اكتملت عملية البناء بنجاح! (Success)                " -ForegroundColor Green
    Write-ColorHost "============================================================" -ForegroundColor Green
    Write-ColorHost "[+] استغرق البناء: $($buildStopwatch.Elapsed.TotalSeconds.ToString('F1')) ثانية" -ForegroundColor White
    Write-ColorHost "[+] مسار المخرجات التنفيذية: $outDir" -ForegroundColor Cyan
    Write-ColorHost ""
    Write-ColorHost "البرامج التنفيذية المتاحة الآن في مجلد البناء الخارجي:" -ForegroundColor Yellow

    $exes = Get-ChildItem -Path $outDir -Filter "*.exe" -ErrorAction SilentlyContinue
    foreach ($exe in $exes) {
        $sizeKb = [Math]::Round($exe.Length / 1KB, 1)
        Write-ColorHost "  -> $($exe.Name.PadRight(25)) ($sizeKb KB)" -ForegroundColor Gray
    }

    # 7. تشغيل البرنامج إذا كان الخيار محدداً
    if ($doRun) {
        $exeToRun = Join-Path $outDir "DevConfigStudio.exe"
        if (-not (Test-Path $exeToRun)) {
            $exeToRun = Join-Path $outDir "MonitoringStudio.exe"
        }

        if (Test-Path $exeToRun) {
            Write-ColorHost ""
            Write-ColorHost "[🚀] جاري تشغيل الواجهة: $exeToRun" -ForegroundColor Green
            Start-Process -FilePath $exeToRun
        } else {
            Write-ColorHost "[!] لم يتم العثور على الملف التنفيذي للتشغيل: $exeToRun" -ForegroundColor Red
        }
    }

} catch {
    Write-ColorHost ""
    Write-ColorHost "============================================================" -ForegroundColor Red
    Write-ColorHost "                 خطأ أثناء عملية البناء                     " -ForegroundColor Red
    Write-ColorHost "============================================================" -ForegroundColor Red
    Write-ColorHost "[X] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
