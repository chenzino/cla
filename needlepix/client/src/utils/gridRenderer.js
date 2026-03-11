export function renderGrid(canvas, grid, palette, cellSize, showGridLines = true) {
  const ctx = canvas.getContext('2d');
  const rows = grid.length;
  const cols = grid[0].length;

  canvas.width = cols * cellSize;
  canvas.height = rows * cellSize;

  // Draw cells
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const colorIndex = grid[r][c];
      const color = palette[colorIndex];
      ctx.fillStyle = color?.dmcHex || color?.hex || '#FFFFFF';
      ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
    }
  }

  // Draw grid lines
  if (showGridLines && cellSize >= 5) {
    ctx.strokeStyle = 'rgba(0,0,0,0.1)';
    ctx.lineWidth = 0.5;

    for (let r = 0; r <= rows; r++) {
      const isMajor = r % 10 === 0;
      if (isMajor) {
        ctx.strokeStyle = 'rgba(0,0,0,0.3)';
        ctx.lineWidth = 1;
      } else {
        ctx.strokeStyle = 'rgba(0,0,0,0.1)';
        ctx.lineWidth = 0.5;
      }
      ctx.beginPath();
      ctx.moveTo(0, r * cellSize);
      ctx.lineTo(cols * cellSize, r * cellSize);
      ctx.stroke();
    }

    for (let c = 0; c <= cols; c++) {
      const isMajor = c % 10 === 0;
      if (isMajor) {
        ctx.strokeStyle = 'rgba(0,0,0,0.3)';
        ctx.lineWidth = 1;
      } else {
        ctx.strokeStyle = 'rgba(0,0,0,0.1)';
        ctx.lineWidth = 0.5;
      }
      ctx.beginPath();
      ctx.moveTo(c * cellSize, 0);
      ctx.lineTo(c * cellSize, rows * cellSize);
      ctx.stroke();
    }
  }

  return canvas;
}
