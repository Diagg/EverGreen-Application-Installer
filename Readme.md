# Greenstaller
Application management 100% in the cloud


## Description
Greenstaller is a tool aimed at managing (package/deploy/update) your core applications entirely from the cloud.
With Greenstaller you can safely deploy your favorite applications (Chrome/7zip/Adobe/Java.. whatever...) with the foolowing benefits:

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

Greenstaller doesn't either needs to create package to customize installation. the logic and Knowledge historically embedded in packages is now publicly shared on Github.

If your endpoints are managed by an MDM, Greenstaller will ease application management even further! No need to include application sources in the MDM app. Everything needed is packed in a single command line.

With Greenstaller, there is no need to update MDM application each time a new release is available. Greenstaller embrase the 'set it & forget it' app management mantra.  

If you have internet and admin rights on your endpoints you already have the required infrastructure in place !

## Quick FAQ

What is the difference with [PSAD](https://psappdeploytoolkit.com/) ?
This is the same kind of tool but with cloud in mind from the early inception.

What is the difference with [Patch my PC](https://patchmypc.com/home-updater) ?
Patch my PC can pretty do a hell lots more and offers support. If this no big deal for you or if you simply can't/dont want to pay, you should consider Greenstaller

What is the difference with [winget](https://docs.microsoft.com/en-us/windows/package-manager/winget/) or [Chocolatey](https://chocolatey.org/) ?
Technically, not much, both tools are probably even better. The difference relies in the philosophy: Greenstaller is a free open source community project built with the secret hope of democratizing packaging knowledge and help lonely admins/Packagers in their duty. "If sharing is caring" means something for you, go Greenstaller !

Nice stuff guy, how can i contribute ?
- If you are in a good mood for donation, please give some coins to great guys [Arron Parker](https://ko-fi.com/stealthpuppy) and [Dan Cough](https://packageology.com/about/) project owners of Evergreen and Nevergreen. Without those guys Greenstaller would never have existed.
- If you Know packaging, Powershell or both, you can help debugging, improve, test or submit application install/uninstall methods to support more products.


Diagg/OSD-Couture.com

