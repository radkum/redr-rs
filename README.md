# Ramon-rs

###Directory hierarchy
**ramon-km** - minifilter project 

**ramon-um** - user mode program to configure minifilter

**common** - shared info between driver and client, like ioctl codes

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