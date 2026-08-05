# 4MiB — test/data/dm4y/base.gbc + dm4-yugi.bps

Each creator bottles the same pair, then everyone who can applies each bottle.
Medians of 5 timed runs, warm cache. A ✗ names what happened instead of a number.

## ips
| creator | create | patch | apply: slap | apply: flips | apply: atmosphereIps |
|---|---|---|---|---|---|
| slap | 18ms | 655KiB | 20ms | 10ms | 10ms |
| flips | 12ms | 654KiB | 21ms | 10ms | 9ms |

## ips32
| creator | create | patch | apply: slap | apply: atmosphereIps |
|---|---|---|---|---|
| slap | 15ms | 672KiB | 21ms | 9ms |
| sips | 8ms | 899KiB | 15ms | 9ms |

## ebp
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 16ms | 655KiB | 22ms |

## ups
| creator | create | patch | apply: slap | apply: flips | apply: goUps |
|---|---|---|---|---|---|
| slap | 9ms | 888KiB | 15ms | 39ms | 12ms |
| goUps | 12ms | 888KiB | 16ms | 39ms | 12ms |

## aps-gba
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 24ms | 1.8MiB | 29ms |

## bps
| creator | create | patch | apply: slap | apply: flips |
|---|---|---|---|---|
| slap | 57ms | 276KiB | 34ms | 38ms |
| flips | 327ms | 272KiB | 28ms | 38ms |

## ppf1
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 10ms | 905KiB | 15ms |

## ppf2
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 10ms | 906KiB | 15ms |

## ppf3
| creator | create | patch | apply: slap | apply: applyppf3 |
|---|---|---|---|---|
| slap | 12ms | 1.8MiB | 15ms | 31ms |
| slap-no-undo | 11ms | 922KiB | 16ms | 30ms |
| makeppf3 | 10ms | 937KiB | 16ms | 38ms |

## ninja1
| creator | create | patch | apply: slap | apply: ninjaPhp |
|---|---|---|---|---|
| slap | 17ms | 888KiB | 21ms | ✗ gave up after 15s |
| ninjaPhp | 41ms | 899KiB | 22ms | ✗ gave up after 15s |

## ninja2
| creator | create | patch | apply: slap | apply: ninja2Php |
|---|---|---|---|---|
| slap | 19ms | 891KiB | 23ms | 65ms |
| ninja2Php | 145ms | 903KiB | 25ms | 65ms |

## dps
| creator | create | patch | apply: slap |
|---|---|---|---|
| slap | 11ms | 898KiB | 14ms |

## gdiff
| creator | create | patch | apply: slap | apply: javaxdelta |
|---|---|---|---|---|
| slap | 18ms | 600KiB | 18ms | 48ms |
| javaxdelta | 136ms | 747KiB | 22ms | 61ms |

## bsdiff
| creator | create | patch | apply: slap | apply: bsdiff |
|---|---|---|---|---|
| slap | 74ms | 204KiB | 44ms | 27ms |
| bsdiff | 560ms | 215KiB | 44ms | 29ms |

## xdelta1
| creator | create | patch | apply: slap | apply: xdelta1 |
|---|---|---|---|---|
| slap | 44ms | 239KiB | 30ms | 19ms |
| xdelta1 | 41ms | 239KiB | 31ms | 19ms |

## xdelta3
| creator | create | patch | apply: slap | apply: xdelta3 |
|---|---|---|---|---|
| slap | 76ms | 218KiB | 35ms | 16ms |
| xdelta3 | 47ms | 236KiB | 43ms | 16ms |

## rfc-vcdiff
| creator | create | patch | apply: slap | apply: xdelta3 |
|---|---|---|---|---|
| slap | 161ms | 318KiB | 25ms | ✗ xdelta3: VCD_CODETABLE support was removed: XD3_UNIMPLEMENTED |
