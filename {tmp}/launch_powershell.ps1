$pythonPath = $null

try {
    # Try to retrieve Python installation path from HKLM
    $regKeyLM = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $regSubKeyLM = $regKeyLM.OpenSubKey('SOFTWARE\Python\PythonCore\3.8\InstallPath')
    if ($regSubKeyLM) {
        $pythonPath = $regSubKeyLM.GetValue('ExecutablePath')
    }
} catch {
    # Ignore any errors and continue to the next step
}

# If not found in HKLM, try to retrieve Python installation path from HKCU
if (-not $pythonPath) {
    try {
        $regKeyCU = [Microsoft.Win32.RegistryKey]::OpenBaseKey('CurrentUser', 'Registry64')
        $regSubKeyCU = $regKeyCU.OpenSubKey('SOFTWARE\Python\PythonCore\3.8\InstallPath')
        if ($regSubKeyCU) {
            $pythonPath = $regSubKeyCU.GetValue('ExecutablePath')
        }
    } catch {
        # Ignore any errors and continue to the next step
    }
}

if (-not $pythonPath) {
    Write-Host "Failed to retrieve Python installation path!"
    exit 1
}

$pythonScript = Join-Path $PSScriptRoot 'medusa.py'
Start-Process -FilePath $pythonPath -ArgumentList $pythonScript -WindowStyle Hidden