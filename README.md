# Layout remapper
Another pure 100% vibe coded, AI generated project. This was created a while ago and uses PyQt6 instead of PySide6 by Claude Sonnet 4.6.

## Usage
Add a  `.layout` file to the same folder as the script. The `.layout` files for colemak-dh-ansi-angle, DVORAK, and Canary have been provided.
There are 3 methods of input:
* WH_KEYBOARD_LL hook. This is legacy, but hey, if it works it works
* Win32 API SendInput. This is better and most people should use this
* Kernel level input remapping for those over-engineers. Requires [Interception by Oblitum][https://github.com/oblitum/Interception] installed. **WARNING: This works for log-in screens too.**

When you run it, an icon will appear in your traybar. Settings are opened in a rather unconventional fashion of middle clicking the icon. Right click closes it. Left click to cycle through layouts (sorted by alphabetical order). It also remembers your last layout on startup.
