function PSDecode {
    [CmdletBinding()]
    param(
        [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
        [PSObject[]]$InputObject
       )

$Invoke_Expression_Override = @'
function Invoke-Expression()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
        Write-Host $Command
    }
'@

$Invoke_Command_Override = @'
function Invoke-Command ()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
        Write-Host $Command
    }
'@

$Invoke_Item_Override = @'
function Invoke-Item()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $true)]
            [String]$Command
        )
        Write-Host $Command
    }
'@

    $override_functions = @()
    $encoded_script = ""
    $layers = @()

    if ($PSCmdlet.MyInvocation.ExpectingInput) {
        #from pipe
        $encoded_script = $InputObject
    }
    else {
        try {
                #from file
                $encoded_script = Get-Content $InputObject -ErrorAction Stop
            }
        catch {
                throw "Error reading: '$($InputObject)'"
            }
    }

    $override_functions += $Invoke_Expression_Override
    $override_functions += $Invoke_Command_Override
    $override_functions += $Invoke_Item_Override

    $decoder = ($override_functions -join "`r`n") + "`r`n`r`n" + $encoded_script

    while($layers -notcontains $encoded_script){
        $layers += $encoded_script
        $encoded_script = powershell $decoder
        if ($LastExitCode -ne 0 -Or $encoded_script.StartsWith("Exception")){
            Break
            }
        $decoder = ($override_functions -join "`r`n`r`n") + "`r`n`r`n" + $encoded_script
         }

    for ($i=0; $i -le $layers.length-1; $i++){
        $heading = "`r`n`r`n" + "#"*30 + " Layer " + ($i+1) + " " + "#"*30
        Write-Host $heading
        Write-Host $layers[$i]
        }  
}
