# Memory Safety Research Project

A repository for all code and documents relevant to a research project looking into vulnerabilities due to memory safety and their mitigations(or lack thereof) in memory safe languages.

## Directories

more directories may be added, we'll try to keep this up to date

### Proposal

the Latex or Typst code used to generate the paper(s)

#### Compiling

TODO

### src

Name pending, the source code used to aggregate data from [CWEs related to memory safety](https://cwe.mitre.org/data/definitions/1399.html) and [NVD](https://nvd.nist.gov/)

probably will be using [poetry](https://python-poetry.org/) for managing dependencies

#### Installation

TODO

### C examples

a (planned to be) compilable list of examples of each type of vulnerability being investigated. Not sure if it will be a single binary where you can pass a command arg, or just a list of smaller binaries per vulnerability

#### Compilation

TODO

### Rust examples

A (planned to be) compilable (or not) list of examples of each. This will likely be multiple binaries, as some of these will intentionally not compile to demonstrate the compile time restrictions which avoid the investigated vulnerability.

#### Compilation

TODO

### Go Examples

same thing as the above 2, but in go. 

#### Compilation
TODO

## Setting up the environment

Recommended software:
- visual studio code
  - with the following extensions installed:
    - Python Language Server
    - Black (formatter for python)
    - Latex Workshop or (Typst LSP)
    - Rust Analyzer
    - (Maybe) CodeLLDB
- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- compilers:
  - [clang](https://clang.llvm.org/get_started.html) or [MVSC](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170)
  - [rust toolchain](https://www.rust-lang.org/tools/install)
  - [go](https://go.dev/doc/install)
  
  depending on which we decide to use:
  - [Latex](https://www.latex-project.org/get/)
  - [Typst](https://github.com/typst/typst)

