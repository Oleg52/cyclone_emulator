# Cyclone Smartcard Emulator

This project emulates MSID-FAID encryption logic for DCT4 phones for Classic Cyclone Box.

Classic Cyclone Box runs encryption code on smartcard gated by credits, when credits run out it cannot be used anymore(server is dead, cannot refill).

Cyclone installer is available on [Mega](https://mega.nz/file/YDcB1DxD#xD2wxST6p0ZJKuWwhyrC2GtmYQVU65hbrJGaz9ZYk5M) (password 1)

After installing, place `winmm.dll` file in the folder with `Cyclone.exe`.

## Build Environment

This project is built using Microsoft Visual Studio 6.0 (VS6).

Emulator project compiles into DLL. It should be named `winmm.dll` for app to load it automatically on startup.

## Acknowledgements

Portions of the reverse-engineering analysis, particularly the identification and understanding of hashing functions, were assisted by AI tools.