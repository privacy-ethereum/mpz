//! Load balancing algorithms.

/// Evenly distributes items across lanes based on their weight.
pub(crate) fn distribute_by_weight<F, T>(
    items: impl IntoIterator<Item = T>,
    f_weight: F,
    num_lanes: usize,
) -> Vec<Vec<T>>
where
    F: Fn(&T) -> usize,
{
    if num_lanes == 0 {
        return Vec::new();
    }

    // Compute weights and pair with items
    let mut items_with_weights: Vec<(T, usize)> = items
        .into_iter()
        .map(|item| {
            let weight = f_weight(&item);
            (item, weight)
        })
        .collect();

    // Sort in decreasing order of weight
    items_with_weights.sort_by(|a, b| b.1.cmp(&a.1));

    let mut lanes: Vec<Vec<T>> = (0..num_lanes).map(|_| Vec::new()).collect();
    let mut lane_weights = vec![0; num_lanes];
    for (item, weight) in items_with_weights {
        // Find the lane with minimum total weight
        let idx = lane_weights
            .iter()
            .enumerate()
            .min_by_key(|&(_, w)| w)
            .unwrap()
            .0;

        lanes[idx].push(item);
        lane_weights[idx] += weight;
    }

    lanes
}
