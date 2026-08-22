package ueba

import (
	"math"
	"sort"
)

// BuildVolumeStats derives classical and robust scores from completed volume
// windows. The caller supplies the current partial window separately so it is
// never included in its own baseline.
func BuildVolumeStats(current int, historical []int) VolumeStats {
	result := VolumeStats{CurrentCount: current, Samples: len(historical)}
	if len(historical) == 0 {
		return result
	}
	values := make([]float64, len(historical))
	for index, value := range historical {
		values[index] = float64(value)
		result.Mean += float64(value)
	}
	result.Mean /= float64(len(values))
	for _, value := range values {
		delta := value - result.Mean
		result.StdDev += delta * delta
	}
	result.StdDev = math.Sqrt(result.StdDev / float64(len(values)))
	result.Median = median(values)
	deviations := make([]float64, len(values))
	for index, value := range values {
		deviations[index] = math.Abs(value - result.Median)
	}
	result.MAD = median(deviations)
	if result.StdDev > 0 {
		result.ZScore = (float64(current) - result.Mean) / result.StdDev
	}
	if result.MAD > 0 {
		result.RobustZScore = 0.6745 * (float64(current) - result.Median) / result.MAD
	}
	return result
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	middle := len(ordered) / 2
	if len(ordered)%2 == 1 {
		return ordered[middle]
	}
	return (ordered[middle-1] + ordered[middle]) / 2
}
