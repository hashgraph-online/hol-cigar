import math
import unittest

from compare_releases import LABELS, order, paired_change


class ReleaseComparisonTests(unittest.TestCase):
    def test_three_treatment_order_balances_all_positions(self):
        orders = [order(i) for i in range(6)]
        self.assertEqual(len(set(orders)), 6)
        for index in range(3):
            for label in LABELS:
                self.assertEqual(sum(row[index] == label for row in orders), 2)

    def test_paired_regression_is_not_hidden_by_unequal_cohort_scale(self):
        result = paired_change([1, 2, 3, 4, 5], [1.5, 3, 4.5, 6, 7.5], 10)
        self.assertFalse(result["guardrail_passed"])
        self.assertEqual(result["median_increase_percent"], 50)
        self.assertEqual(result["descriptive_95_percent_interval"], [50, 50])

    def test_repeated_calls_cannot_replace_missing_process_cohorts(self):
        for left, right in (
            ([1] * 4, [1] * 4),
            ([1] * 5, [1] * 6),
            ([1] * 5, [0] * 5),
            ([math.nan] * 5, [1] * 5),
        ):
            with self.subTest(left=left, right=right), self.assertRaises(ValueError):
                paired_change(left, right, 10)


if __name__ == "__main__":
    unittest.main()
