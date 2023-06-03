[![Github CI](https://github.com/ChimeHQ/gogsym/workflows/CI/badge.svg)](https://github.com/ChimeHQ/gogsym/actions)

# gogsym

Go library for reading GSYM files.

GSYM is a binary file format useful for performing symbolication. It is much smaller and more efficient than using a dSYM.

A format definition can be derived from the LLVM [headers](https://github.com/llvm/llvm-project/tree/main/llvm/include/llvm/DebugInfo/GSYM) and [sources](https://github.com/llvm/llvm-project/tree/main/llvm/lib/DebugInfo/GSYM).

## usage

```go
f, _ := os.Open("my.gsym")
g, _ := NewGsymWithReader(f)
lr, _ := g.LookupTextRelativeAddress(0x3291)
```

# llvm-gsymutil

`llvm-gsymutil` can create and read gsym files. You can build it from the LLVM sources. It takes a long time to build.

    cmake -DLLVM_ENABLE_PROJECTS="llvm-gsymutil" llvm
    make llvm-gsymutil
    bin/llvm-gsymutil -h

## Suggestions or Feedback

We'd love to hear from you! Get in touch via an issue or pull request.

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
