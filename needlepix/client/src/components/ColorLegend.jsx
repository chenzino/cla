export default function ColorLegend({ palette, grid }) {
  // Count stitches per color
  const counts = new Array(palette.length).fill(0);
  for (const row of grid) {
    for (const idx of row) {
      if (idx >= 0 && idx < counts.length) counts[idx]++;
    }
  }
  const totalStitches = counts.reduce((a, b) => a + b, 0);

  // Sort by stitch count descending
  const sorted = palette
    .map((color, i) => ({ ...color, index: i, count: counts[i] }))
    .sort((a, b) => b.count - a.count);

  return (
    <div>
      <h3 className="text-lg font-bold text-gray-800 mb-3">Color Legend</h3>
      <div className="space-y-2">
        {sorted.map((color) => (
          <div key={color.index} className="flex items-center gap-3 text-sm">
            <div
              className="w-6 h-6 rounded border border-gray-300 shrink-0"
              style={{ backgroundColor: color.dmcHex || color.hex }}
            />
            <div className="font-bold text-gray-700 w-14">
              {color.dmc ? `DMC ${color.dmc}` : `#${color.index}`}
            </div>
            <div className="text-gray-500 flex-1 truncate">
              {color.dmcName || color.name}
            </div>
            <div className="text-gray-400 text-xs whitespace-nowrap">
              {color.count.toLocaleString()} ({((color.count / totalStitches) * 100).toFixed(1)}%)
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 pt-3 border-t border-gray-200 text-xs text-gray-400">
        Total: {totalStitches.toLocaleString()} stitches
      </div>
    </div>
  );
}
