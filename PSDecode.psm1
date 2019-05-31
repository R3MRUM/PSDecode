<#
.SYNOPSIS
    Obfuscated PowerShell Script Decoder
.DESCRIPTION
    This is a PowerShell script for deobfuscating other encoded PowerShell scripts. Often, malicious PowerShell scripts have several layers of encodings (Replace, Base64Decode, etc...) that, once decoded, are executed via a call to Invoke-Expression (IEX, &, .), Invoke-Command, etc... This script employs a technique called method overriding that enables us to essentially intercept calls to functions that I have accounted for within this script and print out the arguments being passed to it (a.k.a what the script was trying to execute).

    ** Important Note: Only run this script within an isolated sandbox. If the encoded powershell attempts to execute a function which I have not accounted for, there is a chance it could execute.**
.NOTES
    File Name  : PSDecode.psm1
    Author     : @R3MRUM
	Version    : 3.1
.LINK
    https://github.com/R3MRUM/PSDecode
.LINK
    https://twitter.com/R3MRUM
.LINK
    https://r3mrum.wordpress.com/
.EXAMPLE
    PSDecode .\encoded_ps.ps1

.EXAMPLE
    Get-Content .\encoded_ps.ps1 | PSDecode 
.COMPONENT
#>

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
        Write-Host "%#[Invoke-Command] Execute/Open: $($Command)"
    }
'@

$Invoke_Item_Override = @'
function Invoke-Item()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Item
        )
        Write-Host "%#[Invoke-Item] Execute/Open: $($Item)"
    }
'@

$Get_Item_Override = @'
function Get-Item()
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Item
        )
        $myHashtable = @{
                            Item = $Item
                        }
        $getitem_obj = [PsCustomObject]$myHashtable
        Add-Member -Membertype ScriptProperty -InputObject $getitem_obj -Name Length -Value {
            $get_item_return_val = 100000
            Write-Host "%#[Get-Item.length] Retrieving length of $($get_item_return_val) for: $($this.Item)"
            return $get_item_return_val
            }
        return $getitem_obj
    }
'@

$New_Object_Override = @'
function new-object {
        param(
            [Parameter(Mandatory=$True, Valuefrompipeline = $True)]
            [object[]]$Obj
        )

        if($Obj -ieq 'System.Net.WebClient' -or $Obj -ieq 'Net.WebClient'){
            $webclient_obj = microsoft.powershell.utility\new-object Net.WebClient
            Add-Member -memberType ScriptMethod -InputObject $webclient_obj -Force -Name "DownloadFile" -Value {
                param([string]$url,[string]$destination)
                Write-Host "%#[System.Net.WebClient.DownloadFile] Download From: $($url) --> Save To: $($destination)"
                }
            Add-Member -memberType ScriptMethod -InputObject $webclient_obj -Force -Name "DownloadString" -Value {
                param([string]$url)
                Write-Host "%#[System.Net.WebClient.DownloadString] Download from: $($url)"
                }
            return $webclient_obj
        }
        elseif($Obj -ieq 'random'){
            $random_obj = microsoft.powershell.utility\new-object Random
            Add-Member -memberType ScriptMethod -InputObject $random_obj -Name "next" -Value {
                param([int]$min,[int]$max)
                $random_int = Get-Random -Minimum $min -Maximum $max
                Write-Host "%#[System.Random] Generate random integer between $($min) and $($max). Value returned: $($random_int)"
                return $random_int
                }
            return $random_obj
        }
        else{
            $unk_obj = microsoft.powershell.utility\new-object $Obj
            Write-Host "%#[Error] Undefined object type found: $($Obj)"
            return $unk_obj
        }
    }
'@

function Get_Encoding_Type {
    param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$input_bytes
        )
     if($input_bytes[0] -eq 0xEF -and $input_bytes[1] -eq 0xBB -and $input_bytes[2] -eq 0xBF){
        return 'UTF8'
        }
    elseif($input_bytes[0] -eq 0xFE -and $input_bytes[1] -eq 0xFF){
        return 'UTF16-BE'
        }
    elseif($input_bytes[0] -eq 0xFF -and $input_bytes[1] -eq 0xFE){
        return 'UTF16-LE'
        }
    elseif($input_bytes[1] -eq 0x00 -and $input_bytes[3] -eq 0x00 -and $input_bytes[5] -eq 0x00 -and $input_bytes[7] -eq 0x00 `
      -and $input_bytes[0] -ne 0x00 -and $input_bytes[2] -ne 0x00 -and $input_bytes[4] -ne 0x00 -and $input_bytes[6] -ne 0x00){
        return 'UTF16-LE'
        }
    elseif($input_bytes[0] -eq 0x00 -and $input_bytes[2] -eq 0x00 -and $input_bytes[4] -eq 0x00 -and $input_bytes[6] -eq 0x00 `
      -and $input_bytes[1] -ne 0x00 -and $input_bytes[3] -ne 0x00 -and $input_bytes[5] -ne 0x00 -and $input_bytes[7] -ne 0x00){
        return 'UTF16-BE'
        }
    else {
        return 'ASCII'
        }
}

function Base64_Decode {
    param(
        [Parameter(Mandatory=$True)]
        [String[]]$b64_encoded_string
       )

    try{
        if($b64_encoded_string -match '^TVqQ'){
            return [Byte[]][Convert]::FromBase64String($b64_encoded_string)
            }

        $b64_decoded_ascii = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($b64_encoded_string))

        if($b64_decoded_ascii -match '^(.\x00){8,}’){
            return [System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String($b64_encoded_string))
            }
        else{
            return $b64_decoded_ascii
            }
        }
    catch{
        $ErrorMessage = $_.Exception.Message
        return $false
        }
}

function Replace_Parens
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"(?i)(?<!split)\(\s*'[^']*'\)"
       $matches = $str_format_pattern.Matches($Command) 

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                $Command = $Command.Replace($match, $match.ToString().replace('(','').replace(')',''))
                }
            $matches = $str_format_pattern.Matches($Command) 
        }
       
       return $Command

    }

function Resolve_String_Formats
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )

       $str_format_pattern = [regex]"\(`"({\d+})+`"\s*-f\s*('[^']*',?)+\)"
       $matches = $str_format_pattern.Matches($Command) 

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                $resolved_string = IEX($match)
                $Command = $Command.Replace($match, "'$($resolved_string)'")
                }
            $matches = $str_format_pattern.Matches($Command) 
        }
       
       return $Command
    }

function String_Concat_Cleanup
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       
       return $Command.Replace("'+'", "").Replace('"+"','')
    }

function Code_Cleanup
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )

       $old_command = ''
       $new_command = $Command

       While($old_command -ne $new_command)
       {
            $old_command = $new_command

            $new_command = Replace_Parens($new_command)
            $new_command = String_Concat_Cleanup($new_command)
            $new_command = Resolve_String_Formats($new_command)
        }
        
        return $new_command

    }

function Beautify
    {
        param(
            [Parameter(Mandatory=$True)]
            [char[]]$Command
        )

        $prev_char = ''
        $tabs = 0
        $tab = "`t"
        $newline = "`r`n"
        $new_str = ''
        $in_str = $false
        $curr_quote_chr = ''
        $str_quotes = '"', "'"
        $append_chars = ''

        forEach($char in $Command){
            if($char -contains $str_quotes -and $in_str -eq $false){
                $curr_quote_chr=$char
                $in_str = $true
            }
            elseif($char -contains $str_quotes -and $in_str -eq $true -and $curr_quote_chr -eq $char -and $prev_char -ne '`'){
                $curr_quote_chr=''
                $in_str = $false
            }
            elseif($char -eq '{' -and $in_str -eq $false){
                $append_chars = $newline + ($tab*++$tabs)
            }
            elseif($char -eq '}' -and $in_str -eq $false){
                $append_chars = $newline + ($tab*--$tabs)
            }
            elseif($char -eq ';' -and $in_str -eq $false){
                $append_chars = $newline + ($tab*$tabs)
            }

            $new_str = $new_str + $char + $append_chars
            $prev_char = $char
            $append_chars = ''
        }
    return $new_str
}

function PSDecode {
    [CmdletBinding()]
    param(
        [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
        [PSObject[]]$InputObject
       )

    $layers  = New-Object System.Collections.Generic.List[System.Object]
    $actions = New-Object System.Collections.Generic.List[System.Object]

    $override_functions = @()
    $encoded_script = ""

    if ($PSCmdlet.MyInvocation.ExpectingInput) {
        #from pipe
        $encoded_script = $InputObject

    }
    else {
        try {
                #from file
                $script_bytes = Get-Content $InputObject -Encoding byte -ErrorAction Stop
                $enc_type = Get_Encoding_Type($script_bytes) 
                if($enc_type -eq 'UTF16-LE' ){
                    $encoded_script = [System.Text.Encoding]::UNICODE.GetString($script_bytes)
                }
                elseif($enc_type -eq 'UTF16-BE' ){
                    $encoded_script = [System.Text.Encoding]::BigEndianUnicode.GetString($script_bytes)
                }
                elseif($enc_type -eq 'UTF8'){
                    $encoded_script = [System.Text.Encoding]::UTF8.GetString($script_bytes)
                }else{
                    $encoded_script = [System.Text.Encoding]::ASCII.GetString($script_bytes)
                }

                $b64_decoded = Base64_Decode($encoded_script)

                if($b64_decoded){
                    $layers.Add($encoded_script)
                    $encoded_script = $b64_decoded
                }
            }
        catch {
                throw "Error reading: $($InputObject)"
            }
    }

    $override_functions += $Invoke_Expression_Override
    $override_functions += $Invoke_Command_Override
    $override_functions += $Invoke_Item_Override
    $override_functions += $Get_Item_Override
    $override_functions += $New_Object_Override

    $decoder = ($override_functions -join "`r`n") + "`r`n`r`n" + ($encoded_script -replace("``","") -replace('"','\"') -replace("'\s*'", "''"))


 
    while($layers -notcontains $encoded_script -and -not [string]::IsNullOrEmpty($encoded_script)){

        $layers.Add($encoded_script -replace("``","") -replace("'\+'","") -replace("'\s*'", "''"))

        $encoded_script = (powershell $decoder)

        if (-not [string]::IsNullOrEmpty($encoded_script) -and $encoded_script.GetType().FullName -eq "System.Object[]" -and $encoded_script -match '%#'){
           $actions = $encoded_script.split('%#',[System.StringSplitOptions]::RemoveEmptyEntries).Trim()
           Break
        }

        ElseIf (-not $?){
            Break
            }
        
        $decoder = ($override_functions -join "`r`n`r`n") + "`r`n`r`n" + ($encoded_script -replace("``","") -replace('"','\"') -replace("'\s*'", "''"))
         }

    if($layers.Count -gt 0){
        $last_layer = $layers[-1]
        $str_fmt_res = Code_Cleanup($last_layer)
        
        if($str_fmt_res -ne $last_layer){
            $layers.Add($str_fmt_res)
            }

        ForEach ($layer in $layers){
            $heading = "`r`n`r`n" + "#"*30 + " Layer " + ($layers.IndexOf($layer)+1) + " " + "#"*30
            Write-Host $heading
            Write-Host $layer
            }
        }

        $beautiful_str = Beautify($str_fmt_res)
        $heading = "`r`n`r`n" + "#"*25 + " Beautified Layer " + "#"*26
        Write-Host $heading
        Write-Host $beautiful_str

    if($actions.Count -gt 0){
        $heading = "`r`n`r`n" + "#"*30 + " Actions " + "#"*30
        Write-Host $heading        

        for ($counter=0; $counter -lt $actions.Length; $counter++){
            $line = "{0,5}. {1}" -f ($counter+1),$actions[$counter]
            Write-Host $line
            }
        }
}