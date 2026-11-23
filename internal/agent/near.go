package agent

import "strings"

// shortKey is the length below which only one edit counts as a typo, since
// two edits turn most short words into other words.
const shortKey = 5

// NearKey is the known key that key is most likely a typo of, or "" when
// none is close or two are equally close. Close means the same apart from
// case, or at most two edits (one for keys under shortKey chars), where an
// edit adds, drops or changes a char or swaps two next to each other.
func NearKey(key string, known []string) string {
	limit := 2
	if len(key) < shortKey {
		limit = 1
	}
	best, bestDist, tie := "", limit+1, false
	for _, k := range known {
		d := edits(strings.ToLower(key), strings.ToLower(k))
		switch {
		case d < bestDist:
			best, bestDist, tie = k, d, false
		case d == bestDist:
			tie = true
		}
	}
	if tie || bestDist > limit {
		return ""
	}
	return best
}

// edits is the optimal string alignment distance between a and b: the
// Levenshtein distance plus swaps of two neighbouring chars.
func edits(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
