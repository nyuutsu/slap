# 16MiB — test/data/ffta/base.gba + test/data/ffta/ffta-x.aps

Each creator bottles the same pair, then everyone who can applies each bottle.
Medians of 5 timed runs, warm cache. A ✗ names what happened instead of a number.

## ips
| creator | create | patch | apply: slap | apply: flips | apply: atmosphereIps |
|---|---|---|---|---|---|
| slap | 9ms | 16KiB | 33ms | 30ms | 27ms |
| flips | 21ms | 16KiB | 32ms | 31ms | 27ms |

## ips32
| creator | create | patch | apply: slap | apply: atmosphereIps |
|---|---|---|---|---|
| slap | 11ms | 18KiB | 32ms | 27ms |
| sips | 17ms | 23KiB | 34ms | 27ms |

## ebp
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 11ms | 17KiB | 34ms |

## ups
| creator | create | patch | apply: slap | apply: flips | apply: goUps |
|---|---|---|---|---|---|
| slap | 11ms | 11KiB | 35ms | 137ms | 30ms |
| goUps | 24ms | 11KiB | 33ms | 138ms | 30ms |

## aps-gba
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 13ms | 768KiB | 38ms |

## bps
| creator | create | patch | apply: slap | apply: flips |
|---|---|---|---|---|
| slap | 103ms | 10KiB | 35ms | 136ms |
| flips | 1.29s | 12KiB | 35ms | 136ms |

## ppf1
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 19ms | 17KiB | 32ms |

## ppf2
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 19ms | 18KiB | 32ms |

## ppf3
| creator | create | patch | apply: slap | apply: applyppf3 |
|---|---|---|---|---|
| slap | 19ms | 32KiB | 32ms | 37ms |
| slap-no-undo | 19ms | 24KiB | 31ms | 19ms |
| makeppf3 | 14ms | 33KiB | 33ms | 20ms |

## ninja1
| creator | create | patch | apply: slap | apply: ninjaPhp |
|---|---|---|---|---|
| slap | 45ms | 18KiB | 60ms | ✗ gave up after 15s |
| ninjaPhp | 53ms | 23KiB | 60ms | ✗ gave up after 15s |

## ninja2
| creator | create | patch | apply: slap | apply: ninja2Php |
|---|---|---|---|---|
| slap | 50ms | 22KiB | 64ms | 51ms |
| ninja2Php | 103ms | 28KiB | 64ms | 52ms |

## dps
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 20ms | 46KiB | 32ms |

## gdiff
| creator | create | patch | apply: slap | apply: javaxdelta |
|---|---|---|---|---|
| slap | 12ms | 21KiB | 33ms | 55ms |
| javaxdelta | 249ms | 33KiB | 31ms | 54ms |

## bsdiff
| creator | create | patch | apply: slap | apply: bsdiff |
|---|---|---|---|---|
| slap | 110ms | 8KiB | 112ms | 59ms |
| bsdiff | 2.65s | 8KiB | 111ms | 58ms |

## xdelta1
| creator | create | patch | apply: slap | apply: xdelta1 |
|---|---|---|---|---|
| slap | 45ms | 13KiB | 65ms | 46ms |
| xdelta1 | 49ms | 17KiB | 64ms | 47ms |

## xdelta3
| creator | create | patch | apply: slap | apply: xdelta3 |
|---|---|---|---|---|
| slap | 21ms | 10KiB | 35ms | 32ms |
| xdelta3 | 34ms | 13KiB | 35ms | 32ms |

## rfc-vcdiff
| creator | create | patch | apply: slap | apply: xdelta3 |
|---|---|---|---|---|
| slap | 27ms | 14KiB | 35ms | ✗ xdelta3: VCD_CODETABLE support was removed: XD3_UNIMPLEMENTED |
