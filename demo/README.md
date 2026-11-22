# Windows demo fixture

Build from a Visual Studio Developer Command Prompt:

```bat
cl /nologo /Zi /O2 /Ob0 /c optimized_locals.cpp /Fo:optimized_locals.obj
link /DEBUG /OUT:optimized_locals.exe optimized_locals.obj
```

Open `optimized_locals.exe` in IDA, load `optimized_locals.pdb` with a PDB loader that imports optimized local register ranges, then inspect `copy_prefix` in the decompiler. Compiler versions can choose different registers and live ranges; confirm the fixture produces at least one PDB-backed register variable before using it as a contest demo.
