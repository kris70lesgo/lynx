# Lynx

Lynx helps an analyst carry an optimized PDB local-variable name from IDA's disassembly view into matching Hex-Rays pseudocode.

## First version

Lynx reads register-variable names and address ranges already stored in the IDA database. It compares each range with the defining address and register of a Hex-Rays local variable. It suggests a rename only when the local is still an automatically generated `vN` name and the match is unique. The analyst reviews the evidence and confirms each rename.

Lynx does not load or parse PDB files itself. The PDB loader must import optimized local ranges into IDA's register-variable table. Lynx also does not split or reconstruct a local that Hex-Rays did not allocate.

## Requirements

- IDA 9.4 or later.
- The Hex-Rays decompiler for the binary's architecture.
- A PDB loader that makes optimized local register ranges visible through IDA's register-variable API.

## Install for local development

Copy `lynx.py` and the `lynx` folder into your IDA user plugins directory. The plugin appears as **Lynx — PDB local mapper** under **Edit → Plugins** and can be run with `Ctrl+Shift+L`.

## Use

1. Load a Windows binary and its PDB using a loader that imports optimized local register ranges.
2. Open the function's pseudocode and place the cursor inside that function.
3. Run Lynx.
4. Review a suggestion's name, register, local definition address, and PDB live range.
5. Select a row and confirm the rename.

## Demo fixture

`demo/optimized_locals.cpp` is a small MSVC sample. The build notes explain how to compile it with optimized code and PDB debug information on Windows.

## Matching rules

- Uses the existing Hex-Rays local's defining address and register.
- Requires that address to be inside the PDB register-variable range.
- Normalizes common x86/x64 and ARM64 register aliases.
- Leaves user-renamed locals, ambiguous matches, and name collisions unchanged.
- Never applies a rename without an explicit confirmation.

## Development status

This is an early implementation. It has not yet been run inside IDA because IDA is not installed on the current Mac. The first functional check must use IDA 9.4+ with the Hex-Rays decompiler on Windows or another supported host.
