<#
.SYNOPSIS
    Диагностика ошибки 0x8000401A (CO_E_SERVER_EXEC_FAILURE) при создании V83.COMConnector.

.DESCRIPTION
    Скрипт собирает всё, что нужно для точного вывода о причине сбоя:
      1. Сведения о хосте, разрядности процесса и текущей учётной записи.
      2. Регистрацию ProgID/CLSID/AppID в 64- и 32-битной ветках реестра.
      3. Настройки DCOM-приложения: Identity (RunAs), Launch/Access Permission, AuthenticationLevel.
      4. Состояние учётной записи запуска в AD/локально: блокировка, срок пароля, отключение.
      5. Машинные ограничения COM (MachineLaunchRestriction / MachineAccessRestriction).
      6. Реальную попытку создания COM-объекта с расшифровкой HRESULT.
      7. События DCOM (System) и отказы входа 4625 (Security) за последние N часов.
      8. Доступность сервера 1С по DNS и портам кластера.
      9. Учётные записи пулов IIS (частый вызывающий процесс).
    Итог печатается в консоль и сохраняется в текстовый файл.

.PARAMETER Server
    FQDN сервера 1С для проверки сети, например 3d-1C.DEVINORU.DEVINO.LOCAL

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Diag-COMConnector.ps1 -Server 3d-1C.DEVINORU.DEVINO.LOCAL

.NOTES
    Запускать НА ТОЙ МАШИНЕ, ГДЕ ВЫПОЛНЯЕТСЯ New-Object("V83.COMConnector"),
    от имени администратора (иначе не читаются журнал Security и часть веток реестра).
#>

[CmdletBinding()]
param(
    [string]   $ProgId      = 'V83.COMConnector',
    [string]   $Server      = '',
    [int[]]    $Ports       = @(1540, 1541, 1560, 1561, 1562),
    [int]      $EventHours  = 24,
    [switch]   $SkipComTest,
    [string]   $OutFile     = ''
)

$ErrorActionPreference = 'Continue'
if (-not $OutFile) {
    $OutFile = Join-Path $env:TEMP ("comconnector-diag_{0}_{1:yyyyMMdd-HHmmss}.txt" -f $env:COMPUTERNAME, (Get-Date))
}

try { Start-Transcript -Path $OutFile -Force | Out-Null } catch { Write-Warning "Не удалось начать транскрипт: $($_.Exception.Message)" }

$script:Findings = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Kv {
    param([string]$Key, $Value)
    if ($null -eq $Value -or "$Value" -eq '') { $Value = '<не задано>' }
    Write-Host ("  {0,-32} : {1}" -f $Key, $Value)
}

function Add-Finding {
    param([ValidateSet('OK','WARN','FAIL','INFO')][string]$Level, [string]$Text)
    $script:Findings.Add("[$Level] $Text") | Out-Null
}

# ----------------------------------------------------------------------------
# 1. Окружение
# ----------------------------------------------------------------------------
Write-Section '1. ОКРУЖЕНИЕ'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Kv 'Дата/время'            (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')
Write-Kv 'Компьютер'             ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName)
Write-Kv 'Домен'                 $env:USERDNSDOMAIN
Write-Kv 'ОС'                    ((Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).Version)
Write-Kv 'Скрипт выполняется от'  ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-Kv 'Права администратора'  $isAdmin
Write-Kv 'Разрядность процесса'  $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' })
Write-Kv 'Разрядность ОС'        $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' })
Write-Kv 'Версия PowerShell'     $PSVersionTable.PSVersion

if (-not $isAdmin) { Add-Finding WARN 'Скрипт запущен без прав администратора: журнал Security и часть настроек DCOM могут быть недоступны.' }
if ([Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    Add-Finding INFO 'Процесс 64-битный. Если вызывающее приложение 32-битное, повторите запуск в C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
}

# ----------------------------------------------------------------------------
# 2-3. Регистрация COM и настройки DCOM
# ----------------------------------------------------------------------------
function ConvertTo-Sddl {
    param([byte[]]$Bytes)
    if (-not $Bytes) { return $null }
    try {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $Bytes, 0
        return $sd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
    } catch { return "<ошибка разбора: $($_.Exception.Message)>" }
}

function Show-ComAcl {
    param([byte[]]$Bytes, [ValidateSet('Launch','Access')][string]$Kind, [string]$Label)

    Write-Host "  --- $Label ---"
    if (-not $Bytes) {
        Write-Host '      значение отсутствует -> используются машинные умолчания (см. раздел 5)'
        return
    }
    $sd = $null
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $Bytes, 0 }
    catch { Write-Host "      <не удалось разобрать дескриптор: $($_.Exception.Message)>"; return }

    Write-Host ("      SDDL: " + $sd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All))

    foreach ($ace in $sd.DiscretionaryAcl) {
        $who = "$($ace.SecurityIdentifier)"
        try { $who = $ace.SecurityIdentifier.Translate([Security.Principal.NTAccount]).Value } catch { }
        $m = $ace.AccessMask
        $rights = @()
        if ($Kind -eq 'Launch') {
            if ($m -band 2)  { $rights += 'LocalLaunch' }
            if ($m -band 4)  { $rights += 'RemoteLaunch' }
            if ($m -band 8)  { $rights += 'LocalActivation' }
            if ($m -band 16) { $rights += 'RemoteActivation' }
        } else {
            if ($m -band 1)  { $rights += 'Execute' }
            if ($m -band 2)  { $rights += 'LocalAccess' }
            if ($m -band 4)  { $rights += 'RemoteAccess' }
        }
        if (-not $rights) { $rights = @("mask=0x{0:X}" -f $m) }
        Write-Host ("      {0,-10} {1,-45} {2}" -f $ace.AceType, $who, ($rights -join ', '))
    }
}

function Get-ComRegistration {
    param([string]$ProgId, [Microsoft.Win32.RegistryView]$View)

    $r = [ordered]@{
        View = $View.ToString(); Found = $false; Clsid = $null; AppId = $null
        InprocServer32 = $null; LocalServer32 = $null; DllSurrogate = $null
        RunAs = $null; AuthLevel = $null
        LaunchPermission = $null; AccessPermission = $null
    }

    $hkcr = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::ClassesRoot, $View)
    try {
        $k = $hkcr.OpenSubKey("$ProgId\CLSID")
        if (-not $k) { return $r }
        $r.Clsid = $k.GetValue('')
        $r.Found = $true

        $ck = $hkcr.OpenSubKey("CLSID\$($r.Clsid)")
        if ($ck) {
            $r.AppId = $ck.GetValue('AppID')
            $ips = $ck.OpenSubKey('InprocServer32'); if ($ips) { $r.InprocServer32 = $ips.GetValue('') }
            $lss = $ck.OpenSubKey('LocalServer32'); if ($lss) { $r.LocalServer32 = $lss.GetValue('') }
        }

        if ($r.AppId) {
            $ak = $hkcr.OpenSubKey("AppID\$($r.AppId)")
            if ($ak) {
                $r.RunAs            = $ak.GetValue('RunAs')
                $r.DllSurrogate     = $ak.GetValue('DllSurrogate')
                $r.AuthLevel        = $ak.GetValue('AuthenticationLevel')
                $r.LaunchPermission = $ak.GetValue('LaunchPermission')
                $r.AccessPermission = $ak.GetValue('AccessPermission')
            }
        }
    } catch { Write-Warning "Ошибка чтения реестра ($View): $($_.Exception.Message)" }

    return $r
}

$runAsAccounts = @()

foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {

    Write-Section "2. РЕГИСТРАЦИЯ '$ProgId' В ВЕТКЕ $view"
    $reg = Get-ComRegistration -ProgId $ProgId -View $view

    if (-not $reg.Found) {
        Write-Host "  ProgID '$ProgId' в этой ветке НЕ зарегистрирован."
        Add-Finding WARN "ProgID '$ProgId' отсутствует в ветке реестра $view."
        continue
    }

    Write-Kv 'CLSID'           $reg.Clsid
    Write-Kv 'AppID'           $reg.AppId
    Write-Kv 'InprocServer32'  $reg.InprocServer32
    Write-Kv 'LocalServer32'   $reg.LocalServer32
    Write-Kv 'DllSurrogate'    $reg.DllSurrogate
    Write-Kv 'AuthenticationLevel' $reg.AuthLevel

    foreach ($dll in @($reg.InprocServer32, $reg.LocalServer32)) {
        if ($dll) {
            $path = $dll.Trim('"')
            if (Test-Path -LiteralPath $path) {
                $fi = Get-Item -LiteralPath $path
                Write-Kv 'Файл сервера' "$path (существует, версия $($fi.VersionInfo.FileVersion), изменён $($fi.LastWriteTime))"
            } else {
                Write-Kv 'Файл сервера' "$path -- ФАЙЛ НЕ НАЙДЕН"
                Add-Finding FAIL "Зарегистрированный файл COM-сервера не найден на диске: $path (ветка $view). Требуется regsvr32 comcntr.dll нужной версии."
            }
        }
    }

    Write-Host ''
    Write-Host '  --- Identity (вкладка "Удостоверение" в dcomcnfg) ---'
    if ($null -eq $reg.RunAs) {
        Write-Host '      RunAs не задан -> "Запускающий пользователь" (The launching user).'
        Add-Finding OK "Ветка $view : Identity = Запускающий пользователь. Пароль нигде не хранится, 0x8000401A по причине пароля здесь маловероятна."
    }
    elseif ($reg.RunAs -eq 'Interactive User') {
        Write-Host '      RunAs = Interactive User (Интерактивный пользователь).'
        Add-Finding FAIL "Ветка $view : Identity = Интерактивный пользователь. На сервере без активной консольной сессии запуск невозможен -- типичная причина 0x8000401A."
    }
    elseif ($reg.RunAs -match '^NT AUTHORITY\\|^LocalService$|^LocalSystem$|^NetworkService$') {
        Write-Host "      RunAs = $($reg.RunAs) (системная учётная запись, пароль не требуется)."
        Add-Finding INFO "Ветка $view : Identity = $($reg.RunAs)."
    }
    else {
        Write-Host "      RunAs = $($reg.RunAs)  <-- ФИКСИРОВАННАЯ УЧЁТНАЯ ЗАПИСЬ, пароль хранится в LSA."
        $runAsAccounts += $reg.RunAs
        Add-Finding WARN "Ветка $view : Identity = '$($reg.RunAs)'. Именно здесь чаще всего лежит устаревший пароль, дающий 0x8000401A."
    }

    Write-Host ''
    Show-ComAcl -Bytes $reg.LaunchPermission -Kind Launch -Label 'LaunchPermission (Запуск и активация)'
    Write-Host ''
    Show-ComAcl -Bytes $reg.AccessPermission -Kind Access -Label 'AccessPermission (Доступ)'
}

# ----------------------------------------------------------------------------
# 4. Состояние учётных записей запуска
# ----------------------------------------------------------------------------
Write-Section '4. СОСТОЯНИЕ УЧЁТНЫХ ЗАПИСЕЙ ЗАПУСКА (RunAs)'

function Show-AccountState {
    param([string]$Account)

    Write-Host ''
    Write-Host "  Учётная запись: $Account" -ForegroundColor Yellow

    $domain, $name = $null, $Account
    if ($Account -match '^(.+?)\\(.+)$') { $domain = $Matches[1]; $name = $Matches[2] }
    elseif ($Account -match '^(.+?)@(.+)$') { $name = $Matches[1]; $domain = $Matches[2] }

    $isLocal = (-not $domain) -or ($domain -eq '.') -or ($domain -ieq $env:COMPUTERNAME)

    if ($isLocal) {
        try {
            $u = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$name'" -ErrorAction Stop
            if ($u) {
                Write-Kv 'Тип'               'Локальная'
                Write-Kv 'Disabled'          $u.Disabled
                Write-Kv 'Lockout'           $u.Lockout
                Write-Kv 'PasswordExpires'   $u.PasswordExpires
                Write-Kv 'PasswordChangeable' $u.PasswordChangeable
                Write-Kv 'SID'               $u.SID
                if ($u.Disabled) { Add-Finding FAIL "Учётная запись $Account ОТКЛЮЧЕНА." }
                if ($u.Lockout)  { Add-Finding FAIL "Учётная запись $Account ЗАБЛОКИРОВАНА." }
            } else {
                Write-Host '      Локальная учётная запись с таким именем не найдена.'
                Add-Finding FAIL "Учётная запись $Account не найдена на этом компьютере."
            }
        } catch { Write-Warning $_.Exception.Message }
        return
    }

    # Доменная учётная запись через LDAP
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$name))"
        foreach ($p in 'sAMAccountName','distinguishedName','userAccountControl','pwdLastSet','lockoutTime',
                       'accountExpires','msDS-UserPasswordExpiryTimeComputed','lastLogonTimestamp','userPrincipalName') {
            $searcher.PropertiesToLoad.Add($p) | Out-Null
        }
        $res = $searcher.FindOne()
        if (-not $res) {
            Write-Host '      В домене учётная запись не найдена.'
            Add-Finding FAIL "Доменная учётная запись $Account не найдена в каталоге."
            return
        }

        $pv = { param($n) if ($res.Properties[$n].Count) { $res.Properties[$n][0] } else { $null } }
        $uac = [int](& $pv 'useraccountcontrol')

        $flags = @()
        if ($uac -band 0x0002)   { $flags += 'ACCOUNTDISABLE' }
        if ($uac -band 0x0010)   { $flags += 'LOCKOUT' }
        if ($uac -band 0x10000)  { $flags += 'DONT_EXPIRE_PASSWORD' }
        if ($uac -band 0x800000) { $flags += 'PASSWORD_EXPIRED' }
        if ($uac -band 0x400000) { $flags += 'DONT_REQ_PREAUTH' }

        $pwdLastSet = & $pv 'pwdlastset'
        $lockoutT   = & $pv 'lockouttime'
        $acctExp    = & $pv 'accountexpires'
        $pwdExp     = & $pv 'msds-userpasswordexpirytimecomputed'

        Write-Kv 'Тип'                 'Доменная'
        Write-Kv 'DN'                  (& $pv 'distinguishedname')
        Write-Kv 'UPN'                 (& $pv 'userprincipalname')
        Write-Kv 'userAccountControl'  ("0x{0:X} ({1})" -f $uac, ($(if ($flags) { $flags -join ', ' } else { 'нет особых флагов' })))

        if ($pwdLastSet -and [int64]$pwdLastSet -gt 0) {
            $d = [datetime]::FromFileTime([int64]$pwdLastSet)
            Write-Kv 'Пароль изменён'  ("$d  (дней назад: {0:N0})" -f ((Get-Date) - $d).TotalDays)
        } else {
            Write-Kv 'Пароль изменён'  'НИКОГДА / требуется смена при следующем входе'
            Add-Finding FAIL "У $Account установлен флаг 'сменить пароль при следующем входе' -- DCOM-вход невозможен."
        }

        if ($pwdExp -and [int64]$pwdExp -gt 0 -and [int64]$pwdExp -lt 9223372036854775807) {
            $d = [datetime]::FromFileTime([int64]$pwdExp)
            Write-Kv 'Пароль истекает'  $d
            if ($d -lt (Get-Date)) { Add-Finding FAIL "Пароль учётной записи $Account ПРОСРОЧЕН ($d). Прямая причина 0x8000401A." }
            elseif ($d -lt (Get-Date).AddDays(14)) { Add-Finding WARN "Пароль $Account истекает $d -- ошибка повторится. Задайте 'Срок действия пароля не ограничен'." }
        } else {
            Write-Kv 'Пароль истекает'  'не истекает'
        }

        if ($lockoutT -and [int64]$lockoutT -gt 0) {
            Write-Kv 'Заблокирована с'  ([datetime]::FromFileTime([int64]$lockoutT))
            Add-Finding FAIL "Учётная запись $Account заблокирована (lockoutTime задан)."
        }

        if ($acctExp -and [int64]$acctExp -gt 0 -and [int64]$acctExp -lt 9223372036854775807) {
            $d = [datetime]::FromFileTime([int64]$acctExp)
            Write-Kv 'Срок действия УЗ'  $d
            if ($d -lt (Get-Date)) { Add-Finding FAIL "Срок действия учётной записи $Account истёк ($d)." }
        }

        if ($flags -contains 'ACCOUNTDISABLE') { Add-Finding FAIL "Учётная запись $Account отключена в AD." }
        if ($flags -contains 'PASSWORD_EXPIRED') { Add-Finding FAIL "AD сообщает: пароль $Account просрочен." }
    }
    catch {
        Write-Warning "Не удалось опросить AD: $($_.Exception.Message)"
        Add-Finding WARN "Проверка $Account в AD не выполнена (нет связи с доменом или прав)."
    }
}

if ($runAsAccounts.Count -eq 0) {
    Write-Host '  Фиксированные учётные записи запуска не заданы -- проверять нечего.'
} else {
    $runAsAccounts | Select-Object -Unique | ForEach-Object { Show-AccountState -Account $_ }
}

Write-Host ''
Write-Host '  --- Состав группы "Distributed COM Users" ---'
try { & net localgroup "Distributed COM Users" 2>&1 | Write-Host } catch { Write-Host '      группа недоступна' }
try { & net localgroup "Пользователи DCOM" 2>&1 | Out-Null } catch { }

# ----------------------------------------------------------------------------
# 5. Машинные ограничения COM
# ----------------------------------------------------------------------------
Write-Section '5. МАШИННЫЕ ОГРАНИЧЕНИЯ COM (HKLM\SOFTWARE\Microsoft\Ole)'

$ole = 'HKLM:\SOFTWARE\Microsoft\Ole'
foreach ($v in 'DefaultLaunchPermission','MachineLaunchRestriction','DefaultAccessPermission','MachineAccessRestriction') {
    $bytes = $null
    try { $bytes = (Get-ItemProperty -Path $ole -Name $v -ErrorAction Stop).$v } catch { }
    $kind = if ($v -match 'Launch') { 'Launch' } else { 'Access' }
    Show-ComAcl -Bytes $bytes -Kind $kind -Label $v
    Write-Host ''
}
foreach ($v in 'EnableDCOM','LegacyAuthenticationLevel','LegacyImpersonationLevel') {
    try { Write-Kv $v (Get-ItemProperty -Path $ole -Name $v -ErrorAction Stop).$v } catch { Write-Kv $v '<нет>' }
}
try {
    $rpc = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompat' -ErrorAction SilentlyContinue
} catch { }
try {
    $hard = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompat\RequireIntegrityActivationAuthenticationLevel' -ErrorAction SilentlyContinue
    if ($hard) { Write-Kv 'RequireIntegrityActivationAuthenticationLevel' $hard }
} catch { }

# ----------------------------------------------------------------------------
# 6. Боевая попытка создания объекта
# ----------------------------------------------------------------------------
Write-Section '6. ПОПЫТКА СОЗДАНИЯ COM-ОБЪЕКТА'

if ($SkipComTest) {
    Write-Host '  Пропущено по ключу -SkipComTest.'
} else {
    $com = $null
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $com = New-Object -ComObject $ProgId -ErrorAction Stop
        $sw.Stop()
        Write-Host "  УСПЕХ: объект $ProgId создан за $($sw.ElapsedMilliseconds) мс." -ForegroundColor Green
        Write-Kv 'Тип объекта' $com.GetType().FullName
        Add-Finding OK "COM-объект $ProgId создаётся успешно -- DCOM-активация работает под учётной записью $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
        Write-Host '  Строка соединения при этом НЕ проверялась (метод Connect не вызывался).'
    }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        $hr = $ex.HResult
        $hex = ('0x{0:X8}' -f ($hr -band 0xFFFFFFFF))
        Write-Host "  ОШИБКА при создании $ProgId" -ForegroundColor Red
        Write-Kv 'HRESULT'   $hex
        Write-Kv 'Тип'       $ex.GetType().FullName
        Write-Kv 'Сообщение' $ex.Message

        $known = @{
            '0x8000401A' = 'CO_E_SERVER_EXEC_FAILURE -- Windows не смогла запустить процесс COM-сервера. Почти всегда: неверный/просроченный/заблокированный пароль в Identity DCOM-приложения либо Identity = Интерактивный пользователь.'
            '0x80070005' = 'E_ACCESSDENIED -- у вызывающей учётной записи нет прав Launch/Activation на AppID.'
            '0x80040154' = 'REGDB_E_CLASSNOTREG -- класс не зарегистрирован в этой разрядности. Нужен regsvr32 comcntr.dll.'
            '0x80080005' = 'CO_E_SERVER_EXEC_FAILURE (вариант) -- сбой запуска серверного процесса.'
            '0x800706BA' = 'RPC-сервер недоступен -- сеть/фаервол/имя хоста.'
            '0x80070569' = 'Учётной записи запрещён локальный вход (Deny logon locally / as a batch job).'
        }
        if ($known.ContainsKey($hex)) {
            Write-Host ''
            Write-Host "  РАСШИФРОВКА: $($known[$hex])" -ForegroundColor Yellow
            Add-Finding FAIL "$hex -- $($known[$hex])"
        } else {
            Add-Finding FAIL "Создание $ProgId завершилось ошибкой $hex : $($ex.Message)"
        }
    }
    finally {
        if ($com) { try { [Runtime.InteropServices.Marshal]::ReleaseComObject($com) | Out-Null } catch { } }
    }
}

# ----------------------------------------------------------------------------
# 7. Журналы событий
# ----------------------------------------------------------------------------
Write-Section "7. ЖУРНАЛЫ СОБЫТИЙ ЗА ПОСЛЕДНИЕ $EventHours Ч."

$since = (Get-Date).AddHours(-$EventHours)

Write-Host '  --- System / DistributedCOM ---'
try {
    $dcomEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'; ProviderName = 'Microsoft-Windows-DistributedCOM'; StartTime = $since
    } -ErrorAction Stop | Select-Object -First 25
    if ($dcomEvents) {
        $dcomEvents | ForEach-Object {
            Write-Host ("    {0:yyyy-MM-dd HH:mm:ss}  Id={1}  {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(300, ($_.Message -replace '\s+',' ').Length)))
        }
        Add-Finding WARN "Найдено событий DCOM: $($dcomEvents.Count). Обратите внимание на Id 10001 (не удалось запустить сервер) и 10016 (отказ в правах)."
    } else { Write-Host '    событий нет' }
} catch { Write-Host "    нет событий или нет доступа: $($_.Exception.Message)" }

Write-Host ''
Write-Host '  --- Security / 4625 (отказ входа) ---'
try {
    $fails = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -ErrorAction Stop | Select-Object -First 25
    if ($fails) {
        foreach ($e in $fails) {
            $x = [xml]$e.ToXml()
            $get = { param($n) ($x.Event.EventData.Data | Where-Object { $_.Name -eq $n }).'#text' }
            $rawSub = "$(& $get 'SubStatus')".Trim()
            if (-not $rawSub) { $rawSub = "$(& $get 'Status')".Trim() }
            $subVal = 0
            try {
                if ($rawSub -match '^0x') { $subVal = [Convert]::ToInt64($rawSub.Substring(2), 16) }
                elseif ($rawSub)          { $subVal = [Convert]::ToInt64($rawSub) }
            } catch { $subVal = 0 }
            $sub = ('{0:X8}' -f $subVal)
            $reason = switch ("0x$sub") {
                '0xC000006A' { 'неверный пароль' }
                '0xC0000064' { 'пользователь не существует' }
                '0xC0000234' { 'учётная запись заблокирована' }
                '0xC0000072' { 'учётная запись отключена' }
                '0xC000006F' { 'вход вне разрешённых часов' }
                '0xC0000070' { 'вход с этой рабочей станции запрещён' }
                '0xC0000071' { 'пароль просрочен' }
                '0xC0000193' { 'срок действия учётной записи истёк' }
                '0xC0000224' { 'требуется смена пароля' }
                default      { 'см. SubStatus' }
            }
            Write-Host ("    {0:yyyy-MM-dd HH:mm:ss}  УЗ={1}\{2}  LogonType={3}  SubStatus=0x{4} ({5})  Процесс={6}" -f `
                $e.TimeCreated, (& $get 'TargetDomainName'), (& $get 'TargetUserName'), (& $get 'LogonType'), $sub, $reason, (& $get 'ProcessName'))
            Add-Finding FAIL "Отказ входа для $(& $get 'TargetDomainName')\$(& $get 'TargetUserName') : $reason (событие 4625 от $($e.TimeCreated))."
        }
    } else { Write-Host '    отказов входа не зафиксировано' }
} catch { Write-Host "    журнал недоступен (нужны права администратора): $($_.Exception.Message)" }

Write-Host ''
Write-Host '  --- Application: ошибки, упоминающие 1C / comcntr ---'
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1,2; StartTime = $since } -ErrorAction Stop |
        Where-Object { $_.Message -match '1[Cc]|comcntr|COMConnector|1cv8' } |
        Select-Object -First 10 |
        ForEach-Object { Write-Host ("    {0:yyyy-MM-dd HH:mm:ss}  {1}  Id={2}" -f $_.TimeCreated, $_.ProviderName, $_.Id) }
} catch { Write-Host '    нет данных' }

# ----------------------------------------------------------------------------
# 8. Сеть до сервера 1С
# ----------------------------------------------------------------------------
Write-Section '8. ДОСТУПНОСТЬ СЕРВЕРА 1С'

if (-not $Server) {
    Write-Host '  Параметр -Server не задан, проверка сети пропущена.'
} else {
    Write-Kv 'Проверяемый хост' $Server
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Server)
        Write-Kv 'DNS' (($addrs | ForEach-Object { $_.IPAddressToString }) -join ', ')
    } catch {
        Write-Kv 'DNS' "НЕ РАЗРЕШАЕТСЯ: $($_.Exception.Message)"
        Add-Finding FAIL "Имя $Server не разрешается в IP."
    }

    foreach ($p in $Ports) {
        $client = New-Object System.Net.Sockets.TcpClient
        $ok = $false
        try {
            $iar = $client.BeginConnect($Server, $p, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(3000, $false) -and $client.Connected
            if ($ok) { $client.EndConnect($iar) }
        } catch { $ok = $false } finally { $client.Close() }
        Write-Host ("  Порт {0,-6} : {1}" -f $p, $(if ($ok) { 'открыт' } else { 'ЗАКРЫТ/недоступен' }))
        if (-not $ok -and $p -in 1540,1541) { Add-Finding WARN "Порт $p на $Server недоступен (это важно только для этапа Connect, не для 0x8000401A)." }
    }
}

# ----------------------------------------------------------------------------
# 9. Учётные записи пулов IIS (частый вызывающий процесс)
# ----------------------------------------------------------------------------
Write-Section '9. ВЫЗЫВАЮЩИЕ ПРОЦЕССЫ'

try {
    Import-Module WebAdministration -ErrorAction Stop
    Get-ChildItem IIS:\AppPools | ForEach-Object {
        $id = $_.processModel.identityType
        $u  = $_.processModel.userName
        Write-Host ("  AppPool {0,-30} Identity={1} {2}  State={3}" -f $_.Name, $id, $(if ($u) { "($u)" } else { '' }), $_.State)
    }
} catch { Write-Host '  IIS не установлен либо модуль WebAdministration недоступен.' }

Write-Host ''
Write-Host '  --- Службы, работающие от доменных учётных записей ---'
Get-CimInstance Win32_Service |
    Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT Service\\)' } |
    Select-Object Name, StartName, State |
    Format-Table -AutoSize | Out-String | Write-Host

Write-Host '  --- Запущенные процессы 1С / dllhost ---'
Get-Process -Name 'dllhost','ragent','rmngr','rphost','1cv8','1cv8s' -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, StartTime | Format-Table -AutoSize | Out-String | Write-Host

# ----------------------------------------------------------------------------
# ИТОГИ
# ----------------------------------------------------------------------------
Write-Section 'ИТОГИ ДИАГНОСТИКИ'

if ($script:Findings.Count -eq 0) {
    Write-Host '  Явных отклонений не выявлено.'
} else {
    foreach ($f in $script:Findings) {
        $color = switch -Regex ($f) { '^\[FAIL\]' { 'Red' } '^\[WARN\]' { 'Yellow' } '^\[OK\]' { 'Green' } default { 'Gray' } }
        Write-Host "  $f" -ForegroundColor $color
    }
}

Write-Host ''
Write-Host '  ЧТО ДЕЛАТЬ ДАЛЬШЕ:' -ForegroundColor Cyan
Write-Host '   * Есть [FAIL] про Identity/пароль  -> dcomcnfg -> AppID -> Удостоверение: заново ввести пароль'
Write-Host '                                          или переключить на "Запускающий пользователь".'
Write-Host '   * Есть [FAIL] 0x80070005            -> добавить учётную запись вызывающего процесса'
Write-Host '                                          в Launch/Activation Permission.'
Write-Host '   * Есть [FAIL] про файл comcntr.dll  -> regsvr32 нужной версии платформы.'
Write-Host '   * Всё [OK], но приложение падает    -> запустите скрипт от имени учётной записи'
Write-Host '                                          вызывающего процесса и в нужной разрядности.'
Write-Host ''

try { Stop-Transcript | Out-Null } catch { }
Write-Host "Отчёт сохранён: $OutFile" -ForegroundColor Green
