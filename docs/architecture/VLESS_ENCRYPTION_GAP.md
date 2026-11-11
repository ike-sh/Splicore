# VLESS Encryption version boundary

Released v0.4.0 (`cbac3fd1fcfdc76166513cdaa2d4f113497682cb`) does not
implement VLESS Encryption. Its tag and release artifact remain unchanged.
Sudoku is obfuscation and never substitutes for encryption.

The current source restores the native encrypted stream implementation from
v0.3.0 Frozen through the existing single-binary Core, credential vault,
protocol compiler and transport interfaces. See
[VLESS Encryption](../protocol/VLESS_ENCRYPTION.md) for configuration,
independent peer tests, supported combinations, bounds and qualification limits.
The former blanket not_implemented diagnostic has become strict validation
of actual encryption intent; ordinary errors continue to redact caller material.

No new release or Android qualification is implied by this source change.
v2rayNG device import, public-endpoint VPN startup and real Android traffic
remain NOT EXECUTED. A consuming application must pin an independently
accepted official artifact after the restoration is merged and released.
