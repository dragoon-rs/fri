```bash
use benches/
```

## FRI
```bash
let fri_res_path = benches run fri
open $fri_res_path | benches parse fri
```
| stage  | k    | N | bf | rpo | t                | q  | d     |
| ------ | ---- | - | -- | --- | ---------------- | -- | ----- |
| commit | 4096 | 4 | 4  | 1   | 3ms 706µs 234ns |    |       |
| query  | 4096 | 4 | 4  | 1   | 35µs 984ns      | 32 |       |
| verify | 4096 | 4 | 4  | 1   | 167µs 438ns     | 32 | 16384 |

## FRIDA
```bash
let frida_res_path = benches run frida
open $frida_res_path | benches parse frida
```
| stage | k  | m | N | bf | q  | t            |
| ----- | -- | - | - | -- | -- | ------------ |
| prove | 64 | 1 | 4 | 4  | 32 | 218µs 661ns |
| prove | 64 | 2 | 4 | 4  | 32 | 230µs 157ns |
| prove | 64 | 4 | 4 | 4  | 32 | 244µs 55ns  |
| ...   | ...|...|...|... |... | ...         |
