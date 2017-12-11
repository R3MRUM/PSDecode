# PSDecode
PowerShell script for deobfuscating encoded PowerShell scripts. Often, malicious powershell scripts have several layers of encodings  (Replace, Basre64Decode, etc...) that, once decoded, are executed via a call to Invoke-Expression (IEX). This script employs a technique call method overriding where, when the malicious script calls Invoke-Expression (or the different aliases for IEX), the Invoke-Expression function that I have written is executed rather than the original Invoke-Expression. My function simply prints out what would have been executed.

# To Use
1. Paste your obfuscated code at the end of the PSDecode script
2. Execture the PSDecode script
3. Inspect the output. If obfuscation still remains, replace the previous encoding with the new encoding at the end of the script and re-run.

# Future Revisions
This script was just put together quickly to help me with something I was working on. This being said, there is a lot of potential with this functionality that I plan to expand on. For example, having to append the obfuscated code to the end of the script is a cumbersome process, so this would be something I'd like to eliminate in the next revision.
