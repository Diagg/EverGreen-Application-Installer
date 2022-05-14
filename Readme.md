# Greenstaller
Application management 100% in the cloud


## Description
Greenstaller is a tool aimed at managing (package/deploy/update) your core applications entirely from the cloud.
With Greenstaller you can safely deploy your favorite applications (Chrome/7zip/Adobe/Java.. whatever...) with the following benefits:

- No infrastructure/Endpoint management tool required.
- But fully compatible with MECM, MEM and Workspace One.
- No package creation.
- But still the ability to customize your apps.
- No package distribution.
- No package recreation each time editors update their app.
- Always deploy the latest version.
- Control when update are deployed. 
- Or let applications manage on their own.
- Support application reboot.
- Support bulk installation.
- Allow custom wizards to interact with users (planed).
- Open source and Free !!!


Sounds to good to be true ? ..Sure it is !!

Here are few details on how a single script can handle all those features:

Greenstaller doesn't needs to create package because it downloads latest version of application binary directly from authors site using [Evergreen](https://github.com/aaronparker/evergreen) and [NeverGreen](https://github.com/DanGough/Nevergreen).

Greenstaller doesn't either needs to create package to customize installation. the logic and Knowledge historically embedded in packages are now publicly shared on Github.

If your endpoints are managed by an MDM, Greenstaller will ease application management even further: No need to include application sources in the MDM app. Everything needed is packed in a single command line.

With Greenstaller, there is no need to update MDM application each time a new release is available. Greenstaller embrase the 'set it & forget it' app management mantra.  

If you have internet and admin rights on your endpoints you already have the required infrastructure in place !

## Quick F.A.Q

**What is the difference between Greenstaller and [PSAD](https://psappdeploytoolkit.com/) ?**  
This is the same kind of tool, but Greenstaller was built with cloud in mind from the early inception.

**What is the difference between Greenstaller and [Patch my PC](https://patchmypc.com/home-updater) ?**  
Patch my PC can pretty do a hell lots more like reporting or support.  
If those stuffs are no big deal for you or if you simply can't/dont want to pay, you should consider Greenstaller

**What is the difference between Greenstaller and [Winget](https://docs.microsoft.com/en-us/windows/package-manager/winget/) or [Chocolatey](https://chocolatey.org/) ?**  
Technically, not much, both tools are probably even better. The difference relies in the philosophy: Greenstaller is a community project built with the secret hope of pushing the packaging industry in a new direction, democratizing packaging knowledge for standard applications and help lonely admins/Packagers in their duty.  
If "sharing is caring" means something for you, go Greenstaller !

**Nice stuff guy, how can i contribute ?**
If you are in a good mood for donation, please give some coins to great guys [Aaron Parker](https://ko-fi.com/stealthpuppy) and [Dan Cough](https://packageology.com/about/) project owners of Evergreen and Nevergreen. Without those guys Greenstaller would never have existed.  
If you know about packaging, Powershell or both, you can of course help debugging, improve, test or report issue.  
Most appreciated: You can submit application install/uninstall methods in Powershell to support more products.  
The heart of Greenstaller is located in the Applications-Data folder within APPLICATION-Data.ps1 files.
Thoses files described how executables should be installed, uninstalled, customized and even more,  
This the part where everyone can share knowledge and best practices on deploying the most common applications

## Additional credits
NeverGreen - [Dan Cough](https://github.com/DanGough/Nevergreen)  
EverGreen - [Aaron Parker](https://github.com/aaronparker/evergreen)  
PS-SFTA - [DannySys Team](https://github.com/DanysysTeam/PS-SFTA)  
RunHiddenConsole - [Christian Seidlitz](https://github.com/SeidChr/RunHiddenConsole)  
EndPoint Cloud Kit - [Diagg/OSDC](https://github.com/Diagg/EndPoint-CloudKit)

Diagg/OSD-Couture.com

