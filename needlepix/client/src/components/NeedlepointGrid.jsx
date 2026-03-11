import { useRef, useEffect, useState, useCallback } from 'react';
import { renderGrid } from '../utils/gridRenderer.js';

const ZOOM_LEVELS = [0.5, 1, 1.5, 2];

export default function NeedlepointGrid({ grid, palette, metadata }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [tooltip, setTooltip] = useState(null);

  const cols = metadata.cols;
  const rows = metadata.rows;

  const getBaseSize = useCallback(() => {
    const containerWidth = containerRef.current?.clientWidth || 800;
    return Math.max(3, Math.floor(containerWidth / cols));
  }, [cols]);

  useEffect(() => {
    if (!canvasRef.current || !grid.length) return;
    const baseSize = getBaseSize();
    const cellSize = Math.max(3, Math.floor(baseSize * zoom));
    renderGrid(canvasRef.current, grid, palette, cellSize);
  }, [grid, palette, zoom, getBaseSize]);

  function handleMouseMove(e) {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const cellSize = canvas.width / cols;
    const col = Math.floor(x / cellSize);
    const row = Math.floor(y / cellSize);

    if (row >= 0 && row < rows && col >= 0 && col < cols) {
      const colorIndex = grid[row][col];
      const color = palette[colorIndex];
      setTooltip({
        x: e.clientX,
        y: e.clientY,
        row: row + 1,
        col: col + 1,
        color,
      });
    } else {
      setTooltip(null);
    }
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        <span className="text-sm text-gray-500">Zoom:</span>
        {ZOOM_LEVELS.map((z) => (
          <button
            key={z}
            onClick={() => setZoom(z)}
            className={`px-2 py-1 text-xs rounded cursor-pointer ${
              zoom === z ? 'bg-indigo-500 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {z}x
          </button>
        ))}
      </div>

      <div ref={containerRef} className="overflow-auto border border-gray-200 rounded-lg bg-white relative" style={{ maxHeight: '70vh' }}>
        <canvas
          ref={canvasRef}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTooltip(null)}
          className="block"
        />
      </div>

      {tooltip && (
        <div
          className="fixed z-50 bg-gray-800 text-white text-xs px-2 py-1 rounded shadow-lg pointer-events-none"
          style={{ left: tooltip.x + 12, top: tooltip.y - 30 }}
        >
          Row {tooltip.row}, Col {tooltip.col} — {tooltip.color?.dmc ? `DMC ${tooltip.color.dmc}` : ''} {tooltip.color?.name || tooltip.color?.dmcName || ''}
        </div>
      )}

      {metadata.templateId === 'belt' && (
        <p className="text-xs text-indigo-500 mt-2">This is a repeating tile. The pattern repeats ~7 times across the full belt length.</p>
      )}
    </div>
  );
}
