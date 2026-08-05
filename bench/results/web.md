# web lane — web slap vs RomPatcher.js, warm, per-cell patience of 300s

Each cell is its own child process: booted once, calls timed warm, killed at the budget.
Applies are of the same CLI-made slap patch; each create is judged by rebuilding the pair with its own patch.

| tier | format | apply: web slap | apply: rpjs | create: web slap | create: rpjs | patch: web slap | patch: rpjs |
|---|---|---|---|---|---|---|---|
| 4MiB | ips | 22ms | 4ms | 45ms | 36ms | 655KiB | 886KiB |
| 4MiB | ups | 5ms | 12ms | 6ms | 43ms | 888KiB | 888KiB |
| 4MiB | bps | 29ms | 10ms | 60ms | 251.1s | 276KiB | 308KiB |
| 4MiB | ppf | 3ms | 10ms | 5ms | 31ms | 922KiB | 936KiB |
| 4MiB | ebp | 22ms | 3ms | 45ms | 37ms | 655KiB | 886KiB |
| 4MiB | aps | 24ms | 11ms | 6ms | 33ms | 905KiB | 908KiB |
| 4MiB | rup | 12ms | 17ms | 14ms | 61ms | 891KiB | 903KiB |
| 8MiB | ips | 9ms | 14ms | 17ms | 219ms | 554KiB | 556KiB |
| 8MiB | ebp | 8ms | 19ms | 17ms | 220ms | 554KiB | 556KiB |
| 64MiB | ups | 82ms | 98ms | 75ms | 620ms | 4572KiB | 4572KiB |
| 64MiB | bps | 68ms | 48ms | 2.0s | 560ms | 1898KiB | 4466KiB |
| 64MiB | ppf | 43ms | 59ms | 72ms | 421ms | 4695KiB | 4982KiB |
| 64MiB | aps | 37ms | 66ms | 74ms | 412ms | 4619KiB | 4726KiB |
| 64MiB | rup | 176ms | 198ms | 214ms | 789ms | 4538KiB | 4848KiB |
