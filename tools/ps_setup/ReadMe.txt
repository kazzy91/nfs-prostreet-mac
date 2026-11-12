NFS ProStreet Native - Setup (early preview)

This early Setup checks your own copy of Need for Speed: ProStreet (2007, PC) and tells you whether the Mac port can
use it. It can't build the game yet: translating ProStreet's code to the Mac is still being worked on.
It contains no game files. Everything happens on your Mac; nothing is uploaded, and nothing from the game is run or
changed.

You need:
  - An Apple Silicon Mac (M1 or later) with macOS @MIN_MACOS@ or later.
  - Apple's Command Line Tools (free): Setup offers to install them. It uses the Python they include.
  - Your own copy of the PC game: the installed game folder, its nfs.exe, or your disc image (.iso).

Opening the app the first time:
  This app is not notarized by Apple, so macOS blocks it the first time. Open it once, click Done,
  then go to System Settings > Privacy & Security and click "Open Anyway" next to its name.

What the check tells you:
  - Plain code: the port can use this nfs.exe once building is available.
  - Copy-protected (SecuROM): the retail discs' nfs.exe is. The port never removes copy protection, so it needs an
    nfs.exe without it, from a release you own.
  - Packed or modified: not EA's executable as shipped, so it can't be used either.
A disc image is opened read-only, hidden from Finder, and closed again after the check.
