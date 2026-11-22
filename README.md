# Lynx

Lynx helps an analyst carry an optimized PDB local-variable name from IDA's disassembly view into matching Hex-Rays pseudocode.

## First version

Lynx reads register-variable names and address ranges already stored in the IDA database. It compares each range with a Hex-Rays local's defining address and register, then checks that every observed use of that local falls inside a range with the same PDB name. It suggests a rename only when the local is still an automatically generated `vN` name and the match is unique. The analyst reviews the evidence and confirms each rename.

Lynx does not load or parse PDB files itself. The PDB loader must import optimized local ranges into IDA's register-variable table. Lynx skips a local when observed uses cross a gap or a range with another source name; this avoids renaming one combined Hex-Rays local as if it were a single source variable. Lynx does not split or reconstruct locals, and it cannot correct inaccurate decompiler value flow.

## Requirements

- IDA 9.4 or later.
- The Hex-Rays decompiler for the binary's architecture.
- A PDB loader that makes optimized local register ranges visible through IDA's register-variable API.

## Install for local development

Copy `lynx_plugin.py` and the `lynx` folder into your IDA user plugins directory. The plugin appears as **Lynx — PDB local mapper** under **Edit → Plugins** and can be run with `Ctrl+Shift+L`.

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
- Requires the definition to be inside a matching PDB register-variable range.
- Checks every observed pseudocode use against all fragmented ranges carrying the same source name. Ranges can use different registers.
- Normalizes common x86/x64 and ARM64 register aliases.
- Leaves user-renamed locals, ambiguous matches, and name collisions unchanged.
- Saves a rename against the exact decompiler-local location, even if another local has the same displayed name.
- Never applies a rename without an explicit confirmation.

## Development status

This is an early implementation. Automated tests cover the matcher and SDK-shaped test doubles; they do not replace an IDA run. It has not yet been run inside IDA because IDA is not installed on the current Mac. The first functional check must use IDA 9.4+ with the Hex-Rays decompiler on Windows or another supported host.

Run the offline checks from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

The test doubles do not need an IDA installation or license. To run the plugin itself, IDA Free is not enough because Hex-Rays does not include the IDAPython API in Free.
