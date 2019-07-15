<#
.SYNOPSIS
    Obfuscated PowerShell Script Decoder
.DESCRIPTION
    This is a PowerShell script for deobfuscating other encoded PowerShell scripts. Often, malicious PowerShell scripts have several layers of encodings (Replace, Base64Decode, etc...) that, once decoded, are executed via a call to Invoke-Expression (IEX, &, .), Invoke-Command, etc... This script employs a technique called method overriding that enables us to essentially intercept calls to functions that I have accounted for within this script and print out the arguments being passed to it (a.k.a what the script was trying to execute).

    ** Important Note: Only run this script within an isolated sandbox. If the encoded powershell attempts to execute a function which I have not accounted for, there is a chance it could execute.**

.PARAMETER verbose
    PSDecode will describe in greater detail what it is doing during the decoding process. Can be helpful when troubleshooting

.PARAMETER dump
    PSDecode will dump all of the decoded layers to the system's %TEMP% path. Filename will be ib the format <lowercase_MD5_of_original>_layer_<layer_number>.txt.
    For example:
                c924cb080b1c7d9975d59817f96ca874_layer_1.txt
                c924cb080b1c7d9975d59817f96ca874_layer_2.txt
                c924cb080b1c7d9975d59817f96ca874_layer_3.txt

.PARAMETER beautify
    Attempts to beautify the final layer. This typically works well on simpler scripts but might break on more complex scripts. As a result, I've made this optional.

.PARAMETER timeout
    Sets the maximum number of seconds the decoder should be allowed to run before it is timed out and terminated. Default is 60 seconds.
    
.NOTES
    File Name  : PSDecode.psm1
    Author     : @R3MRUM
	Version    : 4.2
.LINK
    https://github.com/R3MRUM/PSDecode
.LINK
    https://twitter.com/R3MRUM
.LINK
    https://r3mrum.wordpress.coom
.EXAMPLE
    PSDecode -verbose -dump -beautify .\encoded_ps.ps1

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
        Write-Host "%#[Invoke-Command] Execute/Open: $($Command)%#"
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
        Write-Host "%#[Invoke-Item] Execute/Open: $($Item)%#"
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
            Write-Host "%#[Get-Item.length] Returning length of $($get_item_return_val) for: $($this.Item)%#"
            return $get_item_return_val
            }
        return $getitem_obj
    }
'@

$New_Object_Override = @'
function new-object {
        param(
            [Parameter(Mandatory=$True, Valuefrompipeline = $True)]
            [string]$Obj
        )

        if($Obj -ieq 'System.Net.WebClient' -or $Obj -ieq 'Net.WebClient'){
            $webclient_obj = microsoft.powershell.utility\new-object Net.WebClient
            Add-Member -memberType ScriptMethod -InputObject $webclient_obj -Force -Name "DownloadFile" -Value {
                param([string]$url,[string]$destination)
                Write-Host "%#[System.Net.WebClient.DownloadFile] Download From: $($url) --> Save To: $($destination)%#"
                }
            Add-Member -memberType ScriptMethod -InputObject $webclient_obj -Force -Name "DownloadString" -Value {
                param([string]$url)
                Write-Host "%#[System.Net.WebClient.DownloadString] Download from: $($url)%#"
                }
            return $webclient_obj
        }
        elseif($Obj -ieq 'random'){
            $random_obj = microsoft.powershell.utility\new-object Random
            Add-Member -memberType ScriptMethod -InputObject $random_obj -Name "next" -Value {
                param([int]$min,[int]$max)
                $random_int = Get-Random -Minimum $min -Maximum $max
                Write-Host "%#[System.Random] Generate random integer between $($min) and $($max). Value returned: $($random_int)%#"
                return $random_int
                }
            return $random_obj
        }
        else{
            $unk_obj = microsoft.powershell.utility\new-object $Obj
            return $unk_obj
        }
    }
'@

function Get_Encoding_Type {
    param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$input_bytes
        )

    Write-Verbose 'Detecting encoding type...'
    $enc_type = ''
    if($input_bytes[0] -eq 0xEF -and $input_bytes[1] -eq 0xBB -and $input_bytes[2] -eq 0xBF){

        $enc_type = 'UTF8'
        }
    elseif($input_bytes[0] -eq 0xFE -and $input_bytes[1] -eq 0xFF){
        $enc_type = 'UTF16-BE-BOM'
        }
    elseif($input_bytes[0] -eq 0xFF -and $input_bytes[1] -eq 0xFE){
        $enc_type = 'UTF16-LE-BOM'
        }
    elseif($input_bytes[1] -eq 0x00 -and $input_bytes[3] -eq 0x00 -and $input_bytes[5] -eq 0x00 -and $input_bytes[7] -eq 0x00 `
      -and $input_bytes[0] -ne 0x00 -and $input_bytes[2] -ne 0x00 -and $input_bytes[4] -ne 0x00 -and $input_bytes[6] -ne 0x00){
        $enc_type = 'UTF16-LE'
        }
    elseif($input_bytes[0] -eq 0x00 -and $input_bytes[2] -eq 0x00 -and $input_bytes[4] -eq 0x00 -and $input_bytes[6] -eq 0x00 `
      -and $input_bytes[1] -ne 0x00 -and $input_bytes[3] -ne 0x00 -and $input_bytes[5] -ne 0x00 -and $input_bytes[7] -ne 0x00){
        $enc_type = 'UTF16-BE'
        }
    else {
        $enc_type = 'ASCII'
        }

    Write-Verbose "Encoding detected: $($enc_type)"
    return $enc_type
}

function Base64_Encode{
    param(
            [Parameter(Mandatory=$True)]
            [String[]]$str
           )

    $Bytes = [System.Text.Encoding]::UNICODE.GetBytes($str)
    $EncodedText =[Convert]::ToBase64String($Bytes)
    return $EncodedText
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

        if($b64_decoded_ascii -match '^(.\x00){8,}'){
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

function Replace_Quotes_FuncName
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"[\.&](\`"|')[a-zA-Z0-9]+(\`"|')\("
       $matches = $str_format_pattern.Matches($Command) 

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "[Replace_Quotes_FuncName] Replacing: $($match)`tWith: $($match.ToString().replace('"','').replace(`"'`",`"`"))"
                $Command = $Command.Replace($match, $match.ToString().replace('"','').replace("'",""))
                }
            $matches = $str_format_pattern.Matches($Command) 
        }
       
       return $Command

    }

function Replace_FuncParensWrappers
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"[\.&]\(('|`")[a-zA-Z-]+('|`")\)"
       $matches = $str_format_pattern.Matches($Command) 

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "[Replace_FuncParensWrappers] Replacing: $($match)`tWith: $($match.ToString().replace('.','').replace('&','').replace("('",'').replace("')",'').replace('("','').replace('")',''))"
                $Command = $Command.Replace($match, $match.ToString().replace('.','').replace('&','').replace("('",'').replace("')",'').replace('("','').replace('")',''))
                }
            $matches = $str_format_pattern.Matches($Command) 
        }
       
       return $Command

    }

function Clean_Func_Calls
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )

       $str_format_pattern = [regex]"\.['`"][a-zA-Z0-9``]+['`"]"
       $matches = $str_format_pattern.Matches($Command) 

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "[Clean_Func_Calls] Replacing: $($match)`tWith: $($match.ToString().replace('(','').replace(')',''))"
                $Command = $Command.Replace($match, $match.ToString().replace('"','').replace("'",''))
                }
            $matches = $str_format_pattern.Matches($Command) 
        }
       
       return $Command

    }

function Replace_Parens
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )
       $str_format_pattern = [regex]"[^a-zA-Z0-9.&(]\(\s*'[^']*'\)"
       $matches = $str_format_pattern.Matches($Command) 

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                Write-Verbose "[Replace_Parens] Replacing: $($match)`tWith: $($match.ToString().replace('(','').replace(')',''))"
                $Command = $Command.Replace($match, $match.ToString().replace('(','').replace(')',''))
                }
            $matches = $str_format_pattern.Matches($Command) 
        }
       
       return $Command

    }

function Replace_NonEscapes
    {
        param(
            [Parameter(Mandatory=$True)]
            [char[]]$Command
        )

        $prev_char = ''
        $new_str = ''
        $in_str = $false
        $curr_quote_chr = ''
        $str_quotes = '"', "'"
        $char_idx_arr = @()

        for ($char=0; $char -lt $Command.Length; $char++){
            if($Command[$char] -in $str_quotes -and -not $in_str){
                $curr_quote_chr=$Command[$char]
                $in_str = $true
            }
            elseif($Command[$char] -in $str_quotes -and $in_str -and $Command[$char] -eq $curr_quote_chr  -and $prev_char -ne '`'){
                $curr_quote_chr=''
                $in_str = $false
            }
            elseif($Command[$char] -eq '`' -and -not $in_str){
                $char_idx_arr += ,$char
            }

            $prev_char = $Command[$char]
        }

        [System.Collections.ArrayList]$newCommand = $Command
        $idx_offset = 0
        
        if($char_idx_arr.Length -gt 0){
            Write-Verbose "$($char_idx_arr.Length) Non-escape characters detected... Removing"
            }

        ForEach($idx in $char_idx_arr){
            $newCommand.RemoveAt($idx-$idx_offset)
            $idx_offset++
        }

    return $newCommand -join ''
}

function Replace_MultiLineEscapes
    {
        param(
            [Parameter(Mandatory=$True)]
            [string]$Command
        )

        $str_format_pattern = [regex]'`\s*\r\n\s*'
        $matches = $str_format_pattern.Matches($Command)


        While ($matches.Count -gt 0){
            if($matches.Count -gt 0){
                Write-Verbose "$($matches.Count) instances of multi-line escape characters detected... Removing"
            }
            ForEach($match in $matches){
                
                $Command = $Command.Replace($match, ' ')
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

       $str_format_pattern = [regex]"\(`"({\d+})+`"\s*-[fF]\s*('[^']*',?)+\)"
       $matches = $str_format_pattern.Matches($Command) 

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                $resolved_string = IEX($match)
                Write-Verbose "[Resolve_String_Formats] Replacing: $($match)`tWith: $($resolved_string)"
                $Command = $Command.Replace($match, "'$($resolved_string)'")
                }
            $matches = $str_format_pattern.Matches($Command) 
        }
       
       return $Command
    }

function Resolve_Replaces
    {
        param(
            [Parameter( `
                Mandatory=$True, `
                Valuefrompipeline = $True)]
            [String]$Command
        )

       $str_format_pattern = [regex]"\(?['`"][^'`"]+['`"]\)?\.(?i)replace\([^,]+,[^\)]+\)"
       $matches = $str_format_pattern.Matches($Command)

       While ($matches.Count -gt 0){
            ForEach($match in $matches){
                $resolved_string = IEX($match)
                $resolved_string = $resolved_string.replace("'","''")
                Write-Verbose "[Resolve_Replaces] Replacing: $($match)`tWith: $($resolved_string)"
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

            $new_command = Replace_MultiLineEscapes($new_command)
            $new_command = Replace_NonEscapes($new_command)
            $new_command = Replace_Quotes_FuncName($new_command)
            $new_command = Clean_Func_Calls($new_command)
            $new_command = Replace_Parens($new_command)
            $new_command = Replace_FuncParensWrappers($new_command)
            $new_command = String_Concat_Cleanup($new_command)
            $new_command = Resolve_String_Formats($new_command)
            $new_command = Resolve_Replaces($new_command)
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

function Get_MD5
    {
        param(
            [Parameter(Mandatory=$True)]
            [byte[]]$strBytes
        )

        $md5obj = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $hash = [System.BitConverter]::ToString($md5obj.ComputeHash($strBytes))

        return $hash.ToLower().Replace('-','')
    }

function Extract_Executables {
    param(
            [Parameter(Mandatory=$True)]
            [System.Text.RegularExpressions.MatchCollection]$exe_pattern_matches
         )
    
    $b64_decoded_exes = New-Object System.Collections.ArrayList  
    forEach($match in $exe_pattern_matches){
        $b64_decoded = Base64_Decode($match)
        if($b64_decoded){
            $b64_decoded_exes.Add($b64_decoded) | Out-Null
        }
    }

    return $b64_decoded_exes

}

function PSDecode {
    [CmdletBinding()]
      param(
            [Parameter(Mandatory=$false)][switch]$dump,
            [Parameter(Mandatory=$false)][switch]$beautify,
            [Parameter(Mandatory=$false)][int]$timeout = 60,
            [Parameter(Mandatory=$True, Valuefrompipeline = $True, Position = 0)][PSObject[]]$InputObject
            )

    $layers  = New-Object System.Collections.Generic.List[System.Object]
    $actions = New-Object System.Collections.Generic.List[System.Object]
    $action_pattern = [regex]'%#\[[^\]]+\][^%]+%#'

    $override_functions = @()
    $encoded_script = ""

    if($timeout -ne 60){
        Write-Verbose "Default timeout of 60 seconds changed to $($timeout)"
    }

    if ($PSCmdlet.MyInvocation.ExpectingInput) {
        Write-Verbose 'Input received from PIPE'
        $script_bytes = [System.Text.Encoding]::ASCII.GetBytes($InputObject)
        $encoded_script = $InputObject | Out-String
    }
    else {
        try {
        Write-Verbose "Input received from file: $($InputObject)"
        $script_bytes = Get-Content $InputObject -Raw -Encoding byte -ErrorAction Stop
        }
        catch {
                throw "Error reading: $($InputObject)"
            }
    }
    
    Write-Verbose "Calculating MD5 of input"
    $md5 = Get_MD5($script_bytes)
    Write-Verbose "MD5: $($md5)"
    $enc_type = Get_Encoding_Type($script_bytes)
    $pref_enc = [System.Text.Encoding]::ASCII

    if($enc_type -eq 'UTF16-LE' ){
        $encoded_script = [System.Text.Encoding]::UNICODE.GetString($script_bytes)
    }
    elseif($enc_type -eq 'UTF16-BE' ){
        $encoded_script = [System.Text.Encoding]::BigEndianUnicode.GetString($script_bytes)
    }
    elseif($enc_type -eq 'UTF16-LE-BOM' ){
        $encoded_script = [System.Text.Encoding]::UNICODE.GetString($script_bytes).substring(2)
    }
    elseif($enc_type -eq 'UTF16-BE-BOM' ){
        $encoded_script = [System.Text.Encoding]::BigEndianUnicode.GetString($script_bytes).substring(2)
    }
    elseif($enc_type -eq 'UTF8'){
    $encoded_script = [System.Text.Encoding]::UTF8.GetString($script_bytes).substring(1)
    }
    else{
        $encoded_script = [System.Text.Encoding]::ASCII.GetString($script_bytes)
    }

    Write-Verbose 'Testing input to see if Base64 encoded'
    $b64_decoded = Base64_Decode($encoded_script)

    if($b64_decoded){
        Write-Verbose 'Input was Base64 encoded. Decoding was successful. Saved original Base64 encoded string as layer'
        $layers.Add($encoded_script)
        $encoded_script = $b64_decoded
    }
    else{
        Write-Verbose 'Input was either not Base64 encoded or was invalid Base64. Treating as non-Base64'
    }

    $override_functions += $Invoke_Expression_Override
    $override_functions += $Invoke_Command_Override
    $override_functions += $Invoke_Item_Override
    $override_functions += $Get_Item_Override
    $override_functions += $New_Object_Override
    $override_functions  = ($override_functions -join "`r`n") + "`r`n`r`n"
    
    Write-Verbose 'Performing code cleanup on initial script'
    $clean_code = Code_Cleanup($encoded_script)

    if($encoded_script -ne $clean_code){
        Write-Verbose 'Code cleanup resulted in script modification. Saving original as layer.'
        $layers.Add($encoded_script)
        $encoded_script = $clean_code
    }

    Write-Verbose 'Building decoder'
    $decoder = $override_functions + $encoded_script

    Write-Verbose 'Base64 encoding decoder'
    $b64_decoder = Base64_Encode($decoder)


    while($layers -notcontains ($encoded_script) -and -not [string]::IsNullOrEmpty($encoded_script)){

        $layers.Add($encoded_script)
        
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "powershell.exe"
        $pinfo.CreateNoWindow = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false

        if($b64_decoder.length -le 12190){
            $pinfo.Arguments = "-EncodedCommand $($b64_decoder)"
        }
        else{
            
            $tmp_file = [System.IO.Path]::GetTempPath() + [GUID]::NewGuid().ToString() + ".ps1"; 
            Write-Verbose "Output script is too large. Writing temp file to: $($tmp_file)"
            Base64_Decode($b64_decoder) | Out-File $tmp_file
            $pinfo.Arguments = "-File $($tmp_file)"
        }

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        Write-Verbose 'Executing decoder'
        $p.Start() | Out-Null

        if(-not $p.WaitForExit($timeout*1000)){
            Write-Host -ForegroundColor Red "$($timeout) second timeout hit when executing decoder. Killing process and breaking out"
            Stop-Process $p
            if ($tmp_file -and (Test-Path $tmp_file)){
                Write-Verbose "Removing temp file that was written to: $($tmp_file)"
                Remove-Item $tmp_file
            }
            break
        }
        
        $encoded_script =$p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()

        if ($tmp_file -and (Test-Path $tmp_file)){
            Write-Verbose "Removing temp file that was written to: $($tmp_file)"
            Remove-Item $tmp_file
            }

        $action_matches = $action_pattern.Matches($encoded_script)

        if($p.ExitCode -eq 0 -and $encoded_script -and $action_matches.Count -eq 0){
            Write-Verbose 'Layer successfully decoded. Moving on to next layer'
            Write-Verbose 'Performing code cleanup on next layer'
            $encoded_script = Code_Cleanup($encoded_script)
            Write-Verbose 'Building new decoder'
            $decoder = ($override_functions -join "`r`n`r`n") + "`r`n`r`n" + $encoded_script
            Write-Verbose 'Base64 encoding new decoder'
            $b64_decoder = Base64_Encode($decoder)
            
        }
        ElseIf($p.ExitCode -eq 0 -and $action_matches.Count -gt 0){
            Write-Verbose 'Final layer processed. Successful exit with actions detected'
            ForEach($action in $action_matches){
                $actions.Add(($action.ToString().Replace('%#','').Trim())) | Out-Null
            }
            Break
        }
        ElseIf($p.ExitCode -ne 0 -and $action_matches.Count -gt 0){
            Write-Verbose 'Final layer processed. Non-zero exit code with actions detected'
            ForEach($action in $action_matches){
                $actions.Add($action.ToSring().Replace('%#','').Trim()) | Out-Null
            }
            $err = $true
            Break
        }
        ElseIf($p.ExitCode -ne 0 -and  $action_matches.Count -eq 0){
            Write-Verbose 'Final layer processed. Non-zero exit code without actions detected'
            $err = $true
            Break
        }
     }

    Write-Verbose 'Processing completed'

    if($layers.Count -gt 0){
        $last_layer = $layers[-1]
        if(-not $noclean){
            $str_fmt_res = Code_Cleanup($last_layer)
        }
        else{
            $str_fmt_res = $last_layer
        }
        
        if($str_fmt_res -ne $last_layer){
            $layers.Add($str_fmt_res)
        }

        $exe_str_format_pattern = [regex]"TVqQ[^'`"]{100,}"
        $exe_matches = $exe_str_format_pattern.Matches($layers[-1])
        $exe_extracted = 

        if($dump){
            
            Write-Host "Saving layers to $([System.IO.Path]::GetTempPath())"

            ForEach ($layer in $layers){
            $out_filename = "$([System.IO.Path]::GetTempPath())$($md5)_layer_$($layers.IndexOf($layer)+1).txt"
            Write-Host "Writing $($out_filename)"
            $layer | Out-File $out_filename
            }

            if($beautify){

                $out_filename = "$([System.IO.Path]::GetTempPath())$($md5)_layer_$($layers.count + 1).txt"
                Write-Host "Writing $($out_filename)"
                Beautify($str_fmt_res) | Out-File $out_filename
            }

            if($exe_matches.Count -gt 0){
                $extracted_exes = Extract_Executables($exe_matches)
                Write-Host "Identified $($exe_matches.Count) potential executable(s). Saving to $([System.IO.Path]::GetTempPath())"
                if($exe_matches.Count -eq 1){
                    $exe_md5 = Get_MD5($extracted_exes)
                    $out_filename = "$([System.IO.Path]::GetTempPath())$($md5)_executable_$($exe_md5).bin"
                    Write-Host "Writing $($out_filename).`tMD5: $($exe_md5)"
                    $extracted_exes | Set-Content $out_filename -Encoding Byte
                }
                Else{
                    ForEach($exe in $extracted_exes){
                        $exe_md5 = Get_MD5($exe)
                        $out_filename = "$([System.IO.Path]::GetTempPath())$($md5)_executable_$($exe_md5).bin"
                        Write-Host "Writing $($out_filename).`tMD5: $($exe_md5)"
                        $exe | Set-Content $out_filename -Encoding Byte
                    }
                }
            }
        }

        ForEach ($layer in $layers){
            $heading = "`r`n`r`n" + "#"*30 + " Layer " + ($layers.IndexOf($layer)+1) + " " + "#"*30
            Write-Host $heading
            Write-Host $layer
        }
    }

    if(-not $err -and -not $stderr){
        if($beautify){
            $beautiful_str = Beautify($str_fmt_res)
            $heading = "`r`n`r`n" + "#"*25 + " Beautified Layer " + "#"*26
            Write-Host $heading
            Write-Host $beautiful_str
        }

        $heading = "`r`n`r`n" + "#"*30 + " Actions " + "#"*30
        Write-Host $heading
         
        if($actions.Count -gt 0){
            for ($counter=0; $counter -lt $actions.Count; $counter++){
                $line = "{0,5}. {1}" -f ($counter+1),$actions[$counter]
                Write-Host $line
                }
            }
        else{
            Write-Host "No actions Identified. Methods executed by the script may not have corresponding override methods defined."
        }
    }
    ElseIf($p.ExitCode -eq 0 -and $stderr){
        $heading = "`r`n`r`n" + "#"*30 + " Warning! " + "#"*31
        $footer = "#"*30 + " Warning! " + "#"*31
        Write-Host -ForegroundColor Yellow $heading
        Write-Host -ForegroundColor Yellow "Exit code: $($p.ExitCode)"
        Write-Host -ForegroundColor Yellow "Decoder script returned successful exit code but also sent the following to stderr:`r`n$($stderr)"
        Write-Host -ForegroundColor Yellow $footer
        }
    ElseIf($p.ExitCode -ne 0 -and -not $stderr){
        $heading = "`r`n`r`n" + "#"*30 + " Warning! " + "#"*31
        $footer = "#"*30 + " Warning! " + "#"*31
        Write-Host -ForegroundColor Yellow $heading
        Write-Host -ForegroundColor Yellow "Exit code: $($p.ExitCode)"
        Write-Host -ForegroundColor Yellow "Decoder script returned non-zero exit code but no error message was sent to stderr. This is likely the result of the malware intentionally terminating its own execuion rather than some kind of decoding failure"
        Write-Host -ForegroundColor Yellow $footer
        }
    ElseIf($p.ExitCode -ne 0 -and $stderr){
        $heading = "`r`n`r`n" + "#"*30 + " Warning! " + "#"*31
        $footer = "#"*30 + " ERROR! " + "#"*31
        Write-Host -ForegroundColor Red -BackgroundColor White $heading
        Write-Host -ForegroundColor Red "Exit code: $($p.ExitCode)"
        Write-Host -ForegroundColor Red $stderr
        Write-Host -ForegroundColor Red -BackgroundColor White $footer
        }

    if($exe_matches.Count -gt 0 -and -not $dump){
        Write-Host -ForegroundColor Yellow "$($exe_matches.Count) possible executable(s) embedded within the encoded script. Rerun PSDecode with -dump switch to attempt to extract"

    }
}