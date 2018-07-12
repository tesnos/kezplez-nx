# kezplez-nx
### Now with 100% more keys!!
## The "easiest" way to get all 70+ Nintendo Switch keys to use with hactool!

## Usage
YOU MUST HAVE DUMPED YOUR FUSES AND TSEC_KEYS BEFORE USING THIS.

Dumping tsec_keys will be an option in the 3.3 release of CTCaer's hekate, for now you must use the build provided in the releases.

1. Launch CTCaer's hekate mod, and dump your kfuses and tsec_keys by going through the menu
* For fuses, Console Info -> Print fuse info -> Press power button
* For tsec_keys, Console Info -> Print TSEC keys -> Press power button
### IF YOU ARE ON 1.0.0 - 2.3.0, ALSO DO THE FOLLOWING IN HEKATE:
* Tools -> Backup -> Backup eMMC BOOT0/1
* Tools -> Dump package1/2

2. Launch CFW so you can access homebrew

3. Via FTPD, Appstore-nx, or some other method of getting files on your switch, put `kezplez-nx.nro` and `kezplez-nx.nacp` in "/switch/kezplez-nx" on your sd card.

4. Launch it, read the information presented, and press A to have the magic happen

Keys will appear at "/keys.txt" on your sd card. In the future, there may be features such as uploading keys to a site like pastebin.com for convenience or a payload version of this application so you can run it in RCM.


## Licensing Information
See LICENSE.md

## Building
Requires libnx + libcurl and libfreetype from the devkitpro pacman switch-portlibs.
Just type `make` and you'll have yourself a fresh build.

Note: requires [this](https://github.com/switchbrew/libnx/pull/130) pr for libnx (Should be merged soon)

## Thanks to...
* SciresM for hactool
* @Stay off my cock#6239 (Shadów on the ReSwitched discord) for knowing you can generate keys for firmwares with only their keyblob seeds and updating the original kezplez to make it much better
* mbedtls
* libcurl
* Team Reswitched
* Everyone who has helped me with my dumb mistakes in the ReSwitched Discord
* Team Switchbrew

## The message "PLEASE stop hurting people and killing the homebrew scene" goes to...
* 4chan
* Team Xecuter
* Bigots