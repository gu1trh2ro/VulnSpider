from __future__ import annotations

import unittest

from vulnspider.reporting import charts
from vulnspider.reporting.charts import Bar, Segment, Slice


class ToneTests(unittest.TestCase):
    def test_known_tones_resolve_to_css_variables(self) -> None:
        self.assertEqual(charts.tone_color("high"), "var(--high)")
        self.assertEqual(charts.tone_color("bac"), "var(--bac)")

    def test_unknown_tone_falls_back_to_neutral_instead_of_interpolating(self) -> None:
        injected = 'red" onload="alert(1)'
        rendered = charts.bar_chart(
            [Bar(label="x", value_label="1", ratio=0.5, tone=injected)]
        )
        self.assertNotIn("onload", rendered)
        self.assertIn("var(--line)", rendered)


class ClampTests(unittest.TestCase):
    def test_ratio_is_clamped_into_unit_range(self) -> None:
        self.assertEqual(charts.clamp_ratio(-3.0), 0.0)
        self.assertEqual(charts.clamp_ratio(0.25), 0.25)
        self.assertEqual(charts.clamp_ratio(4.0), 1.0)

    def test_non_finite_ratio_is_treated_as_zero(self) -> None:
        self.assertEqual(charts.clamp_ratio(float("nan")), 0.0)
        self.assertEqual(charts.clamp_ratio(float("inf")), 1.0)

    def test_bar_width_never_exceeds_one_hundred_percent(self) -> None:
        rendered = charts.bar_chart(
            [Bar(label="over", value_label="9", ratio=12.0, tone="high")]
        )
        self.assertIn("width:100.0%", rendered)


class DonutTests(unittest.TestCase):
    def _donut(self, *values: float) -> str:
        return charts.donut_chart(
            [
                Slice(label="높음", value=values[0], tone="high"),
                Slice(label="보통", value=values[1], tone="medium"),
                Slice(label="낮음", value=values[2], tone="low"),
            ],
            center_value=str(int(sum(values))),
            center_caption="분포",
            empty_caption="없음",
        )

    def test_segments_cover_the_full_circumference(self) -> None:
        rendered = self._donut(1.0, 1.0, 2.0)
        self.assertEqual(rendered.count('class="donut-seg"'), 3)
        self.assertIn("var(--high)", rendered)
        self.assertIn("var(--medium)", rendered)
        self.assertIn("var(--low)", rendered)

    def test_zero_valued_slices_are_omitted_but_kept_in_the_legend(self) -> None:
        rendered = self._donut(2.0, 0.0, 0.0)
        self.assertEqual(rendered.count('class="donut-seg"'), 1)
        self.assertIn("보통", rendered)

    def test_empty_donut_renders_track_only_with_empty_caption(self) -> None:
        rendered = self._donut(0.0, 0.0, 0.0)
        self.assertNotIn('class="donut-seg"', rendered)
        self.assertIn('class="donut-track"', rendered)
        self.assertIn("없음", rendered)

    def test_output_is_deterministic(self) -> None:
        self.assertEqual(self._donut(3.0, 1.0, 2.0), self._donut(3.0, 1.0, 2.0))


class EscapingTests(unittest.TestCase):
    def test_labels_and_captions_are_escaped_everywhere(self) -> None:
        payload = "<script>alert('x')</script>"
        rendered = "".join(
            (
                charts.bar_chart(
                    [
                        Bar(
                            label=payload,
                            value_label=payload,
                            ratio=0.5,
                            tone="high",
                            caption=payload,
                        )
                    ]
                ),
                charts.donut_chart(
                    [Slice(label=payload, value=1.0, tone="high")],
                    center_value=payload,
                    center_caption=payload,
                    empty_caption=payload,
                ),
                charts.stacked_bar(
                    [Segment(label=payload, ratio=0.4, tone="high")], caption=payload
                ),
                charts.chart_card(payload, "<i></i>", english=payload, note=payload),
            )
        )
        self.assertNotIn(payload, rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_escape_text_handles_none(self) -> None:
        self.assertEqual(charts.escape_text(None), "")


class StackedBarTests(unittest.TestCase):
    def test_zero_width_segments_are_dropped(self) -> None:
        rendered = charts.stacked_bar(
            [
                Segment(label="a", ratio=0.5, tone="high"),
                Segment(label="b", ratio=0.0, tone="low"),
            ]
        )
        self.assertEqual(rendered.count("<i "), 1)


class BarChartTests(unittest.TestCase):
    def test_empty_bar_list_renders_the_supplied_caption(self) -> None:
        rendered = charts.bar_chart([], empty_caption="선정된 후보가 없습니다.")
        self.assertIn("선정된 후보가 없습니다.", rendered)
        self.assertNotIn("bar-row", rendered)


if __name__ == "__main__":
    unittest.main()
