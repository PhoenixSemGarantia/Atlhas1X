param([Parameter(Mandatory = $true)][string]$AppDir)

# A interface apenas acompanha uma auditoria local e somente leitura.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$reportsDir = Join-Path $AppDir 'reports'
$scriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$selector = Join-Path $scriptsDir 'Selecionar_Modo_Atlhas1x.ps1'
$auditScript = Join-Path $AppDir 'atlhas1x.py'
$scannerVersion = 'v1.4.2'

if (-not (Test-Path $auditScript) -or -not (Test-Path $selector)) {
    [System.Windows.Forms.MessageBox]::Show('Os arquivos do Atlhas1x nao estao completos.' + [Environment]::NewLine + [Environment]::NewLine + 'Execute instalar_atlhas1x.bat novamente.', 'Atlhas1x - Arquivos ausentes', 'OK', 'Error') | Out-Null
    exit 1
}

# Usa a identificacao declarada pelo proprio scanner para evitar que a janela
# de progresso apresente uma versao diferente do relatorio.
try {
    $versionLine = Select-String -Path $auditScript -Pattern '^VERSION\s*=\s*["'']([^"'']+)["'']' -ErrorAction Stop | Select-Object -First 1
    if ($versionLine -and $versionLine.Matches.Count -gt 0) { $scannerVersion = $versionLine.Matches[0].Groups[1].Value }
} catch { }

# Prefere o Python portatil. Os demais caminhos so sao usados quando o instalador
# encontrou um Python compativel ja instalado no Windows.
$python = Join-Path $AppDir 'runtime\python\python.exe'
$pythonPrefix = ''
if (-not (Test-Path $python)) {
    $pyCommand = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyCommand) {
        $python = $pyCommand.Source
        $pythonPrefix = '-3 '
    } else {
        $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($pythonCommand) { $python = $pythonCommand.Source }
    }
}

if (-not (Test-Path $python)) {
    [System.Windows.Forms.MessageBox]::Show('Nenhum Python compativel foi encontrado.' + [Environment]::NewLine + [Environment]::NewLine + 'Abra instalar_atlhas1x.bat para preparar o Atlhas1x.', 'Atlhas1x - Python necessario', 'OK', 'Warning') | Out-Null
    exit 1
}

$mode = & $selector
if (-not $mode) { exit 0 }
if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null }
$showLiveDetails = $mode -ne 'basic'

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Atlhas1x - Auditoria de Seguranca'
$form.ClientSize = New-Object System.Drawing.Size(550, 290)
if ($showLiveDetails) { $form.ClientSize = New-Object System.Drawing.Size(650, 610) }
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ControlBox = $false

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Executando auditoria de seguranca...'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(28, 28)
$form.Controls.Add($title)

$description = New-Object System.Windows.Forms.Label
$description.Text = 'A auditoria consulta apenas metadados locais.' + [Environment]::NewLine + 'Nenhuma configuracao do Windows sera alterada.'
$description.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$description.AutoSize = $true
$description.Location = New-Object System.Drawing.Point(31, 70)
$form.Controls.Add($description)

$status = New-Object System.Windows.Forms.Label
$status.Text = 'Preparando a coleta...'
$status.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$status.AutoSize = $true
$status.Location = New-Object System.Drawing.Point(31, 122)
$form.Controls.Add($status)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Style = 'Continuous'
$progress.Minimum = 0
$progress.Maximum = 100
$progress.Value = 8
$progress.Size = New-Object System.Drawing.Size(505, 24)
$progress.Location = New-Object System.Drawing.Point(31, 151)
$form.Controls.Add($progress)

$timing = New-Object System.Windows.Forms.Label
$timing.Text = 'Tempo decorrido: 00:00    Calculando estimativa com os primeiros checks...'
$timing.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$timing.AutoSize = $true
$timing.Location = New-Object System.Drawing.Point(31, 188)
$form.Controls.Add($timing)

$note = New-Object System.Windows.Forms.Label
$note.Text = 'O progresso e uma estimativa; algumas maquinas podem levar mais tempo.'
$note.Font = New-Object System.Drawing.Font('Segoe UI', 8)
$note.ForeColor = [System.Drawing.Color]::DimGray
$note.AutoSize = $true
$note.Location = New-Object System.Drawing.Point(31, 214)
$form.Controls.Add($note)

$versionLabel = New-Object System.Windows.Forms.Label
$versionLabel.Text = 'Atlhas1x ' + $scannerVersion + ' - Detection Accuracy & Validation'
$versionLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
$versionLabel.ForeColor = [System.Drawing.Color]::DimGray
$versionLabel.AutoSize = $true
# Mantem a versao visivel tambem durante a coleta detalhada, antes da caixa
# que recebe comandos e respostas em tempo real.
$versionLabel.Location = New-Object System.Drawing.Point(31, 232)
if (-not $showLiveDetails) { $versionLabel.Location = New-Object System.Drawing.Point(31, 252) }
$form.Controls.Add($versionLabel)

$buttonY = 248
$openButtonX = 265
$closeButtonX = 405
if ($showLiveDetails) { $buttonY = 555; $openButtonX = 365; $closeButtonX = 505 }

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancelar auditoria'
$cancelButton.Size = New-Object System.Drawing.Size(150, 32)
$cancelButton.Location = New-Object System.Drawing.Point(31, $buttonY)
$cancelButton.Add_Click({
    if (-not $process.HasExited) {
        $script:cancelRequested = $true
        $cancelButton.Enabled = $false
        $cancelButton.Text = 'Cancelando...'
        $status.Text = 'Cancelando a auditoria local...'
        try { $process.Kill() } catch { }
    }
})
$form.Controls.Add($cancelButton)

$openReportButton = New-Object System.Windows.Forms.Button
$openReportButton.Text = 'Abrir relatorio'
$openReportButton.Size = New-Object System.Drawing.Size(130, 32)
$openReportButton.Location = New-Object System.Drawing.Point($openButtonX, $buttonY)
$openReportButton.Visible = $false
$openReportButton.Add_Click({ $script:nextAction = 'open'; $form.Close() })
$form.Controls.Add($openReportButton)

$closeButton = New-Object System.Windows.Forms.Button
$closeButton.Text = 'Fechar'
$closeButton.Size = New-Object System.Drawing.Size(100, 32)
$closeButton.Location = New-Object System.Drawing.Point($closeButtonX, $buttonY)
$closeButton.Visible = $false
$closeButton.Add_Click({ $script:nextAction = 'close'; $form.Close() })
$form.Controls.Add($closeButton)

$detailsBox = $null
if ($showLiveDetails) {
    $detailsTitle = New-Object System.Windows.Forms.Label
    $detailsTitle.Text = 'Detalhes da auditoria em tempo real (comandos e respostas)'
    $detailsTitle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $detailsTitle.AutoSize = $true
    $detailsTitle.Location = New-Object System.Drawing.Point(31, 246)
    $form.Controls.Add($detailsTitle)

    $detailsBox = New-Object System.Windows.Forms.TextBox
    $detailsBox.Multiline = $true
    $detailsBox.ReadOnly = $true
    $detailsBox.ScrollBars = 'Vertical'
    $detailsBox.WordWrap = $false
    $detailsBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    $detailsBox.BackColor = [System.Drawing.Color]::White
    $detailsBox.Size = New-Object System.Drawing.Size(605, 260)
    $detailsBox.Location = New-Object System.Drawing.Point(31, 271)
    $form.Controls.Add($detailsBox)
}

$process = New-Object System.Diagnostics.Process
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = $python
$startInfo.Arguments = $pythonPrefix + '"' + $auditScript + '" --mode ' + $mode
$script:liveLogPath = Join-Path $reportsDir ('atlhas1x_run_' + (Get-Date -Format 'yyyy-MM-dd_HHmmss') + '.log')
if ($showLiveDetails) {
    New-Item -ItemType File -Path $script:liveLogPath -Force | Out-Null
    $startInfo.Arguments += ' --live-details --live-log "' + $script:liveLogPath + '"'
}
$startInfo.WorkingDirectory = $AppDir
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $false
$startInfo.RedirectStandardError = $true
$process.StartInfo = $startInfo

try { [void]$process.Start() } catch {
    [System.Windows.Forms.MessageBox]::Show('Nao foi possivel iniciar o Atlhas1x.' + [Environment]::NewLine + [Environment]::NewLine + 'Execute instalar_atlhas1x.bat novamente.', 'Atlhas1x - Erro ao iniciar', 'OK', 'Error') | Out-Null
    exit 1
}

$script:exitCode = 1
$script:completed = $false
$script:nextAction = 'close'
$script:cancelRequested = $false
$script:liveLogLength = 0
$script:completedModules = 0
$script:totalModules = 0
$script:currentModule = 'Preparando a coleta...'
$scanStarted = Get-Date
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
    if ($showLiveDetails -and $detailsBox -and (Test-Path $script:liveLogPath)) {
        try {
            $liveText = [System.IO.File]::ReadAllText($script:liveLogPath)
            if ($liveText.Length -gt $script:liveLogLength) {
                $newText = $liveText.Substring($script:liveLogLength)
                $detailsBox.AppendText($newText)
                $script:liveLogLength = $liveText.Length
                foreach ($line in ($newText -split "`r?`n")) {
                    if ($line -match '^\[PROGRESS\]\s+(\d+)\/(\d+)\|(.+)$') {
                        $script:completedModules = [int]$matches[1]
                        $script:totalModules = [int]$matches[2]
                        $script:currentModule = $matches[3]
                    }
                }
                $detailsBox.SelectionStart = $detailsBox.TextLength
                $detailsBox.SelectionLength = 0
                $detailsBox.ScrollToCaret()
            }
        } catch { }
    }

    if (-not $script:completed) {
        $elapsedSeconds = [int]((Get-Date) - $scanStarted).TotalSeconds
        if ($script:totalModules -gt 0 -and $script:completedModules -gt 0) {
            $percent = [Math]::Min(95, [Math]::Max(5, [int][Math]::Round(($script:completedModules / $script:totalModules) * 100)))
            $progress.Value = $percent
            $status.Text = ('Executando check {0} de {1}: {2}' -f $script:completedModules, $script:totalModules, $script:currentModule)
            if ($script:completedModules -ge 2) {
                $estimatedTotal = [Math]::Ceiling(($elapsedSeconds / $script:completedModules) * $script:totalModules)
                $remaining = [Math]::Max(0, $estimatedTotal - $elapsedSeconds)
                $timing.Text = ('Tempo decorrido: {0:mm\:ss}    Estimativa restante: ~{1:mm\:ss}' -f ([TimeSpan]::FromSeconds($elapsedSeconds)), ([TimeSpan]::FromSeconds($remaining)))
            } else {
                $timing.Text = ('Tempo decorrido: {0:mm\:ss}    Calculando estimativa com os primeiros checks...' -f ([TimeSpan]::FromSeconds($elapsedSeconds)))
            }
        } else {
            $status.Text = 'Preparando a coleta...'
            $progress.Value = 5
            $timing.Text = ('Tempo decorrido: {0:mm\:ss}    Calculando estimativa com os primeiros checks...' -f ([TimeSpan]::FromSeconds($elapsedSeconds)))
        }

        if ($process.HasExited) {
            $timer.Stop()
            $process.WaitForExit()
            $script:exitCode = $process.ExitCode
            $script:completed = $true
            $progress.Value = 100
            $form.ControlBox = $true
            $cancelButton.Visible = $false
            $openReportButton.Visible = $true
            $closeButton.Visible = $true
            if ($script:cancelRequested) {
                $title.Text = 'Auditoria cancelada'
                $status.Text = 'A coleta foi interrompida. Nenhuma configuracao do Windows foi alterada.'
                $openReportButton.Text = 'Abrir reports'
            } elseif ($script:exitCode -eq 0) {
                $title.Text = 'Auditoria concluida'
                $status.Text = 'Relatorio HTML gerado. Escolha uma opcao abaixo.'
                $openReportButton.Text = 'Abrir relatorio'
            } else {
                $title.Text = 'Auditoria terminou com erro'
                $errorText = ''
                try { $errorText = $process.StandardError.ReadToEnd().Trim() } catch { }
                $firstLine = ($errorText -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
                $status.Text = if ($firstLine) { 'Erro: ' + $firstLine } else { 'Nao foi possivel obter o detalhe do erro. Execute instalar_atlhas1x.bat novamente.' }
                $openReportButton.Text = 'Abrir reports'
                if ($detailsBox -and $errorText) {
                    $detailsBox.AppendText('[ERROR] ' + $errorText + [Environment]::NewLine)
                    $detailsBox.SelectionStart = $detailsBox.TextLength
                    $detailsBox.ScrollToCaret()
                }
                try { [System.IO.File]::AppendAllText($script:liveLogPath, '[ERROR] ' + $errorText + [Environment]::NewLine) } catch { }
            }
        }
    }
})
$timer.Start()
[void]$form.ShowDialog()

if ($script:exitCode -eq 0) {
    $latest = Get-ChildItem -Path $reportsDir -Filter ('atlhas1x_' + $mode + '_*.html') | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($script:nextAction -eq 'open') {
        if ($latest) { Start-Process $latest.FullName } else { Start-Process explorer.exe $reportsDir }
    }
    exit 0
}

if ($script:nextAction -eq 'open') { Start-Process explorer.exe $reportsDir }
exit $script:exitCode
