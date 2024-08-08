### How to use
#### Installing (with admin rights):
Click right mouse button on Ramon.inf and choose install or type
> RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 C:\VsExclude\kernel\ramon\ramon.inf

#### Start: 
> fltmc load minifilter

#### Setup minifilter:
Todo
> ramon-client.exe 


#### Stop:
> fltmc unload minifilter

###TODO
- better filtering for file events: don't send everything to user mode 