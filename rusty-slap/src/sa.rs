//! SA-IS suffix array construction (Nong, Zhang, Chan 2009).

/// Build the suffix array of `data`.
///
/// Returns a vector of length `data.len()` where entry `i` is the starting
/// position of the `i`-th lexicographically smallest suffix.
#[must_use]
pub fn suffix_array(data: &[u8]) -> Vec<i32> {
    let n = data.len();
    if n == 0 {
        return vec![];
    }
    // Map bytes to 1..=256, append sentinel 0.
    let text: Vec<i32> = data
        .iter()
        .map(|&b| i32::from(b) + 1)
        .chain(std::iter::once(0))
        .collect();
    let mut sa = vec![0i32; n + 1];
    sais(&text, &mut sa, 257);
    sa[1..].to_vec()
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Bucket boundary array for alphabet `[0..k)`.
/// `end = false` → inclusive starts.  `end = true` → exclusive ends.
fn bucket_bounds(text: &[i32], k: usize, end: bool) -> Vec<usize> {
    let mut bkt = vec![0usize; k];
    for &c in text {
        bkt[c as usize] += 1;
    }
    let mut sum = 0;
    for b in bkt.iter_mut() {
        if end {
            sum += *b;
            *b = sum;
        } else {
            let cnt = *b;
            *b = sum;
            sum += cnt;
        }
    }
    bkt
}

/// Induce L-type suffixes (left → right, filling from bucket starts).
fn induce_l(text: &[i32], sa: &mut [i32], is_s: &[bool], k: usize) {
    let n = text.len();
    let mut bkt = bucket_bounds(text, k, false);
    for i in 0..n {
        if sa[i] <= 0 {
            continue;
        }
        let j = sa[i] as usize - 1;
        if !is_s[j] {
            let c = text[j] as usize;
            sa[bkt[c]] = j as i32;
            bkt[c] += 1;
        }
    }
}

/// Induce S-type suffixes (right → left, filling from bucket ends).
fn induce_s(text: &[i32], sa: &mut [i32], is_s: &[bool], k: usize) {
    let n = text.len();
    let mut bkt = bucket_bounds(text, k, true);
    for i in (0..n).rev() {
        if sa[i] <= 0 {
            continue;
        }
        let j = sa[i] as usize - 1;
        if is_s[j] {
            let c = text[j] as usize;
            bkt[c] -= 1;
            sa[bkt[c]] = j as i32;
        }
    }
}

/// True when LMS substrings starting at `a` and `b` are identical.
fn lms_eq(text: &[i32], is_s: &[bool], a: usize, b: usize) -> bool {
    let n = text.len();
    let is_lms = |i: usize| i > 0 && is_s[i] && !is_s[i - 1];
    let mut d = 0;
    loop {
        let ai = a + d;
        let bi = b + d;
        if ai >= n || bi >= n {
            return false;
        }
        if text[ai] != text[bi] || is_s[ai] != is_s[bi] {
            return false;
        }
        if d > 0 {
            match (is_lms(ai), is_lms(bi)) {
                (true, true) => return true,
                (true, false) | (false, true) => return false,
                _ => {}
            }
        }
        d += 1;
    }
}

/// SA-IS on integer alphabet `[0..k)`.
/// `text` must end with a unique sentinel (value 0) smaller than every other value.
fn sais(text: &[i32], sa: &mut [i32], k: usize) {
    let n = text.len();
    match n {
        0 => return,
        1 => {
            sa[0] = 0;
            return;
        }
        2 => {
            sa[0] = 1;
            sa[1] = 0;
            return;
        }
        _ => {}
    }

    // --- classify suffix types: S = true, L = false ---
    let mut is_s = vec![false; n];
    is_s[n - 1] = true;
    for i in (0..n - 1).rev() {
        is_s[i] = text[i] < text[i + 1] || (text[i] == text[i + 1] && is_s[i + 1]);
    }
    let is_lms = |i: usize| i > 0 && is_s[i] && !is_s[i - 1];
    let lms: Vec<usize> = (1..n).filter(|&i| is_lms(i)).collect();

    // --- pass 1: approximate sort to rank LMS substrings ---
    sa.iter_mut().for_each(|x| *x = -1);
    {
        let mut bkt = bucket_bounds(text, k, true);
        for &pos in lms.iter().rev() {
            let c = text[pos] as usize;
            bkt[c] -= 1;
            sa[bkt[c]] = pos as i32;
        }
    }
    induce_l(text, sa, &is_s, k);
    induce_s(text, sa, &is_s, k);

    // --- name LMS substrings ---
    let mut rank = -1i32;
    let mut prev: Option<usize> = None;
    let mut names = vec![0i32; n];
    for &p in sa.iter() {
        if p < 0 || !is_lms(p as usize) {
            continue;
        }
        let pos = p as usize;
        let diff = match prev {
            None => true,
            Some(q) => !lms_eq(text, &is_s, q, pos),
        };
        if diff {
            rank += 1;
        }
        names[pos] = rank;
        prev = Some(pos);
    }
    let num_ranks = (rank + 1) as usize;

    // --- recurse or invert ---
    let sa1 = if num_ranks < lms.len() {
        let reduced: Vec<i32> = lms.iter().map(|&pos| names[pos]).collect();
        let mut sa1 = vec![0i32; lms.len()];
        sais(&reduced, &mut sa1, num_ranks);
        sa1
    } else {
        // All LMS substrings unique — invert names to get SA directly.
        let mut sa1 = vec![0i32; lms.len()];
        for (i, &pos) in lms.iter().enumerate() {
            sa1[names[pos] as usize] = i as i32;
        }
        sa1
    };

    // --- pass 2: exact sort using correct LMS order ---
    sa.iter_mut().for_each(|x| *x = -1);
    {
        let mut bkt = bucket_bounds(text, k, true);
        for i in (0..lms.len()).rev() {
            let pos = lms[sa1[i] as usize];
            let c = text[pos] as usize;
            bkt[c] -= 1;
            sa[bkt[c]] = pos as i32;
        }
    }
    induce_l(text, sa, &is_s, k);
    induce_s(text, sa, &is_s, k);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn naive_sa(data: &[u8]) -> Vec<i32> {
        let mut sa: Vec<i32> = (0..data.len() as i32).collect();
        sa.sort_by(|&a, &b| data[a as usize..].cmp(&data[b as usize..]));
        sa
    }

    /// Deterministic PRNG (SplitMix64).
    fn pseudo_random(seed: u64, n: usize) -> Vec<u8> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state = state.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                z ^= z >> 31;
                z as u8
            })
            .collect()
    }

    #[test]
    fn empty() {
        assert_eq!(suffix_array(&[]), Vec::<i32>::new());
    }

    #[test]
    fn single_byte() {
        assert_eq!(suffix_array(&[42]), vec![0]);
    }

    #[test]
    fn two_bytes() {
        assert_eq!(suffix_array(&[0, 1]), vec![0, 1]);
        assert_eq!(suffix_array(&[1, 0]), vec![1, 0]);
        assert_eq!(suffix_array(&[5, 5]), vec![1, 0]);
    }

    #[test]
    fn banana() {
        assert_eq!(suffix_array(b"banana"), vec![5, 3, 1, 0, 4, 2]);
    }

    #[test]
    fn mississippi() {
        assert_eq!(
            suffix_array(b"mississippi"),
            vec![10, 7, 4, 1, 0, 9, 8, 6, 3, 5, 2]
        );
    }

    #[test]
    fn all_same() {
        assert_eq!(suffix_array(&[b'a'; 4]), vec![3, 2, 1, 0]);
        assert_eq!(suffix_array(&[0u8; 8]), naive_sa(&[0u8; 8]));
    }

    #[test]
    fn ascending() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(suffix_array(&data), naive_sa(&data));
    }

    #[test]
    fn descending() {
        let data: Vec<u8> = (0..=255).rev().collect();
        assert_eq!(suffix_array(&data), naive_sa(&data));
    }

    #[test]
    fn random_200() {
        let data = pseudo_random(0xdeadbeef, 200);
        assert_eq!(suffix_array(&data), naive_sa(&data));
    }

    #[test]
    fn random_1000() {
        let data = pseudo_random(0xcafebabe, 1000);
        assert_eq!(suffix_array(&data), naive_sa(&data));
    }

    #[test]
    fn all_256_values() {
        // Every byte value exactly once, shuffled via Fisher-Yates.
        let mut data: Vec<u8> = (0..=255).collect();
        let mut state = 12345u64;
        for i in (1..256).rev() {
            state = state.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^= z >> 31;
            let j = (z as usize) % (i + 1);
            data.swap(i, j);
        }
        assert_eq!(suffix_array(&data), naive_sa(&data));
    }
}
