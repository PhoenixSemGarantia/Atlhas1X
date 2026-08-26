Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Atlhas1x - Escolha o nivel do relatorio'
$form.Size = New-Object System.Drawing.Size(560, 300)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Qual nivel de detalhe voce deseja?'
$title.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(25, 20)
$form.Controls.Add($title)

$description = New-Object System.Windows.Forms.Label
$description.Text = "Basico: resumo facil de entender.`r`nIntermediario: contexto, recomendacoes e resumo.`r`nAvancado: detalhes tecnicos e inventarios completos."
$description.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$description.AutoSize = $true
$description.Location = New-Object System.Drawing.Point(28, 55)
$form.Controls.Add($description)

$selection = $null
function Add-ModeButton($text, $mode, $x) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $text
    $button.Tag = $mode
    $button.Size = New-Object System.Drawing.Size(150, 42)
    $button.Location = New-Object System.Drawing.Point($x, 190)
    $button.Add_Click({ $script:selection = $this.Tag; $form.Close() })
    $form.Controls.Add($button)
}

Add-ModeButton 'Basico' 'basic' 25
Add-ModeButton 'Intermediario' 'intermediate' 200
Add-ModeButton 'Avancado' 'advanced' 375

[void]$form.ShowDialog()
if ($selection) { Write-Output $selection }
