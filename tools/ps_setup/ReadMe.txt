NFS ProStreet Native - Setup

Setup builds the Mac version of Need for Speed: ProStreet (2007, PC) on your Mac, from your own copy of EA's
ProStreet demo. It contains no game files: it carries this project's source code and builds the game from your files,
here. Nothing is uploaded, and your game folder is only read, never changed.

You need:
  - An Apple Silicon Mac (M1 or later) with macOS @MIN_MACOS@ or later.
  - Apple's Command Line Tools (free): Setup offers to install them. It uses the compilers and Python they include.
  - EA's ProStreet demo, installed (for example with CrossOver): the folder that holds nfsdemo.exe and the demo's
    data. The demo's executable is the one the port supports: EA built it without copy protection.
  - About 4 GB of free disk space.

Opening the app the first time:
  This app is not notarized by Apple, so macOS blocks it the first time. Open it once, click Done,
  then go to System Settings > Privacy & Security and click "Open Anyway" next to its name.

Building:
  1. Choose your ProStreet demo folder (or drop it on the window). Setup checks its executable.
  2. Click Build and Install. Setup recompiles the game's code for Apple silicon, builds the video decoder, audio and
     graphics libraries and the game app, signs it, and installs "NFS ProStreet Native" in Applications. The first
     build takes about 5 minutes; later ones reuse the video decoder.
  3. Click Play.
The game reads your demo folder where it is, so keep it there. Saves and logs: ~/Library/Application Support/NFSPS-port
and ~/Library/Logs/NFSPS-port. Setup's own log: ~/Library/Logs/NFSPS-Setup/build.log.

What the check tells you about an nfs.exe:
  - EA's ProStreet demo executable: supported, Setup can build from it.
  - Plain code, but another build: not supported yet.
  - Copy-protected (SecuROM): the retail discs' nfs.exe is. The port never removes copy protection.
  - Packed or modified: not EA's executable as shipped, so it can't be used either.
A disc image is opened read-only, hidden from Finder, and closed again after the check.
