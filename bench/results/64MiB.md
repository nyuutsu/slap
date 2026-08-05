# 64MiB — test/data/stadium2/base.z64 + test/data/stadium2/fair-heavy/patch.bps

Each creator bottles the same pair, then everyone who can applies each bottle.
Medians of 3 timed runs, warm cache. A ✗ names what happened instead of a number.

## ips32
| creator | create | patch | apply: slap | apply: atmosphereIps |
|---|---|---|---|---|
| slap | 38ms | 4.4MiB | 103ms | 103ms |
| sips | 68ms | 4.7MiB | 127ms | 103ms |

## ups
| creator | create | patch | apply: slap | apply: flips | apply: goUps |
|---|---|---|---|---|---|
| slap | 44ms | 4.5MiB | 126ms | 549ms | 123ms |
| goUps | 99ms | 4.5MiB | 127ms | 548ms | 128ms |

## aps-n64
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 73ms | 4.5MiB | 109ms |

## bps
| creator | create | patch | apply: slap | apply: flips |
|---|---|---|---|---|
| slap | 1.55s | 1.9MiB | 122ms | 532ms |
| flips | 11.94s | 1.8MiB | 121ms | 540ms |

## ppf1
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 71ms | 4.5MiB | 112ms |

## ppf2
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 72ms | 4.5MiB | 111ms |

## ppf3
| creator | create | patch | apply: slap | apply: applyppf3 |
|---|---|---|---|---|
| slap | 80ms | 9.0MiB | 112ms | 207ms |
| slap-no-undo | 74ms | 4.6MiB | 112ms | 109ms |
| makeppf3 | 57ms | 4.9MiB | 125ms | 208ms |

## ninja1
| creator | create | patch | apply: slap | apply: ninjaPhp |
|---|---|---|---|---|
| slap | 130ms | 4.4MiB | 163ms | ✗ gave up after 15s |
| ninjaPhp | 241ms | 4.7MiB | ✗ output differs from the pair | ✗ gave up after 15s |

## ninja2
| creator | create | patch | apply: slap | apply: ninja2Php |
|---|---|---|---|---|
| slap | 204ms | 4.4MiB | 232ms | 232ms |
| ninja2Php | 685ms | 4.7MiB | 251ms | 275ms |

## gdiff
| creator | create | patch | apply: slap | apply: javaxdelta |
|---|---|---|---|---|
| slap | 239ms | 1.9MiB | 110ms | 165ms |
| javaxdelta | 1.27s | 1.9MiB | 106ms | 152ms |

## bsdiff
| creator | create | patch | apply: slap | apply: bsdiff |
|---|---|---|---|---|
| slap | 682ms | 1.9MiB | 471ms | 279ms |
| bsdiff | 14.79s | 1.8MiB | 470ms | 278ms |

## xdelta1
| creator | create | patch | apply: slap | apply: xdelta1 |
|---|---|---|---|---|
| slap | 386ms | 1.7MiB | 238ms | 174ms |
| xdelta1 | 270ms | 1.8MiB | 239ms | 174ms |

## xdelta3
| creator | create | patch | apply: slap | apply: xdelta3 |
|---|---|---|---|---|
| slap | 398ms | 1.7MiB | 152ms | 134ms |
| xdelta3 | 383ms | 1.7MiB | 163ms | 135ms |

## rfc-vcdiff
| creator | create | patch | apply: slap | apply: xdelta3 |
|---|---|---|---|---|
| slap | 359ms | 1.9MiB | 109ms | ✗ xdelta3: VCD_CODETABLE support was removed: XD3_UNIMPLEMENTED |
