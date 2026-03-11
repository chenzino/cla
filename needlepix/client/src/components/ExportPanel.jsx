import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';

export default function ExportPanel({ grid, palette, metadata, prompt }) {
  function handlePngExport() {
    const canvas = document.querySelector('canvas');
    if (!canvas) return;
    const link = document.createElement('a');
    link.download = `needlepix-${metadata.templateId}-${Date.now()}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
  }

  async function handlePdfExport() {
    const pdf = await PDFDocument.create();
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    const fontBold = await pdf.embedFont(StandardFonts.HelveticaBold);

    const { cols, rows } = metadata;
    const cellPt = Math.max(4, Math.min(8, Math.floor(500 / Math.max(cols, rows))));
    const gridWidthPt = cols * cellPt;
    const gridHeightPt = rows * cellPt;

    const margin = 40;
    const headerHeight = 60;

    // Determine page tiling for large grids
    const usableWidth = 612 - margin * 2; // Letter width
    const usableHeight = 792 - margin * 2 - headerHeight;
    const tilesX = Math.ceil(gridWidthPt / usableWidth);
    const tilesY = Math.ceil(gridHeightPt / usableHeight);
    const overlapPx = 2; // cells of overlap

    for (let ty = 0; ty < tilesY; ty++) {
      for (let tx = 0; tx < tilesX; tx++) {
        const page = pdf.addPage([612, 792]);
        const pageHeight = 792;

        // Header
        page.drawText('NeedlePix Pattern', {
          x: margin,
          y: pageHeight - margin - 14,
          size: 14,
          font: fontBold,
          color: rgb(0.2, 0.2, 0.2),
        });

        const subtitle = `${prompt} | ${cols}×${rows} stitches | ${new Date().toLocaleDateString()}`;
        page.drawText(subtitle.substring(0, 80), {
          x: margin,
          y: pageHeight - margin - 30,
          size: 8,
          font,
          color: rgb(0.5, 0.5, 0.5),
        });

        if (tilesX > 1 || tilesY > 1) {
          page.drawText(`Page ${ty * tilesX + tx + 1} of ${tilesX * tilesY} (tile ${tx + 1},${ty + 1})`, {
            x: margin,
            y: pageHeight - margin - 42,
            size: 7,
            font,
            color: rgb(0.6, 0.6, 0.6),
          });
        }

        // Calculate which cells to draw on this tile
        const startCol = tx === 0 ? 0 : Math.floor((tx * usableWidth) / cellPt) - overlapPx;
        const startRow = ty === 0 ? 0 : Math.floor((ty * usableHeight) / cellPt) - overlapPx;
        const endCol = Math.min(cols, startCol + Math.floor(usableWidth / cellPt));
        const endRow = Math.min(rows, startRow + Math.floor(usableHeight / cellPt));

        const originX = margin;
        const originY = pageHeight - margin - headerHeight;

        for (let r = startRow; r < endRow; r++) {
          for (let c = startCol; c < endCol; c++) {
            const colorIndex = grid[r][c];
            const color = palette[colorIndex];
            const hex = color?.dmcHex || color?.hex || '#FFFFFF';
            const { r: cr, g: cg, b: cb } = hexToRgb(hex);

            page.drawRectangle({
              x: originX + (c - startCol) * cellPt,
              y: originY - (r - startRow + 1) * cellPt,
              width: cellPt,
              height: cellPt,
              color: rgb(cr / 255, cg / 255, cb / 255),
            });
          }
        }

        // Grid lines every 10 stitches (darker)
        for (let r = startRow; r <= endRow; r++) {
          const isMajor = r % 10 === 0;
          const y = originY - (r - startRow) * cellPt;
          page.drawLine({
            start: { x: originX, y },
            end: { x: originX + (endCol - startCol) * cellPt, y },
            thickness: isMajor ? 0.8 : 0.2,
            color: rgb(0, 0, 0),
            opacity: isMajor ? 0.5 : 0.15,
          });
        }
        for (let c = startCol; c <= endCol; c++) {
          const isMajor = c % 10 === 0;
          const x = originX + (c - startCol) * cellPt;
          page.drawLine({
            start: { x, y: originY },
            end: { x, y: originY - (endRow - startRow) * cellPt },
            thickness: isMajor ? 0.8 : 0.2,
            color: rgb(0, 0, 0),
            opacity: isMajor ? 0.5 : 0.15,
          });
        }
      }
    }

    // Legend page
    const legendPage = pdf.addPage([612, 792]);
    const lph = 792;
    legendPage.drawText('Color Legend', {
      x: margin,
      y: lph - margin - 14,
      size: 16,
      font: fontBold,
      color: rgb(0.2, 0.2, 0.2),
    });

    legendPage.drawText(`${prompt} | ${metadata.templateId} | ${cols}×${rows}`, {
      x: margin,
      y: lph - margin - 32,
      size: 9,
      font,
      color: rgb(0.5, 0.5, 0.5),
    });

    // Count stitches
    const counts = new Array(palette.length).fill(0);
    for (const row of grid) {
      for (const idx of row) {
        if (idx >= 0 && idx < counts.length) counts[idx]++;
      }
    }
    const totalStitches = counts.reduce((a, b) => a + b, 0);

    const sorted = palette
      .map((color, i) => ({ ...color, index: i, count: counts[i] }))
      .sort((a, b) => b.count - a.count);

    let yPos = lph - margin - 60;
    const lineHeight = 20;

    // Table header
    legendPage.drawText('DMC', { x: margin + 30, y: yPos, size: 8, font: fontBold, color: rgb(0.3, 0.3, 0.3) });
    legendPage.drawText('Color Name', { x: margin + 80, y: yPos, size: 8, font: fontBold, color: rgb(0.3, 0.3, 0.3) });
    legendPage.drawText('Stitches', { x: margin + 300, y: yPos, size: 8, font: fontBold, color: rgb(0.3, 0.3, 0.3) });
    legendPage.drawText('%', { x: margin + 370, y: yPos, size: 8, font: fontBold, color: rgb(0.3, 0.3, 0.3) });
    yPos -= lineHeight;

    for (const color of sorted) {
      if (yPos < margin) break;

      const hex = color.dmcHex || color.hex || '#FFFFFF';
      const { r: cr, g: cg, b: cb } = hexToRgb(hex);

      legendPage.drawRectangle({
        x: margin,
        y: yPos - 4,
        width: 14,
        height: 14,
        color: rgb(cr / 255, cg / 255, cb / 255),
        borderColor: rgb(0.7, 0.7, 0.7),
        borderWidth: 0.5,
      });

      legendPage.drawText(color.dmc || `${color.index}`, {
        x: margin + 30,
        y: yPos,
        size: 9,
        font: fontBold,
        color: rgb(0.2, 0.2, 0.2),
      });

      legendPage.drawText((color.dmcName || color.name || '').substring(0, 35), {
        x: margin + 80,
        y: yPos,
        size: 9,
        font,
        color: rgb(0.4, 0.4, 0.4),
      });

      legendPage.drawText(color.count.toLocaleString(), {
        x: margin + 300,
        y: yPos,
        size: 9,
        font,
        color: rgb(0.4, 0.4, 0.4),
      });

      legendPage.drawText(`${((color.count / totalStitches) * 100).toFixed(1)}%`, {
        x: margin + 370,
        y: yPos,
        size: 9,
        font,
        color: rgb(0.4, 0.4, 0.4),
      });

      yPos -= lineHeight;
    }

    // Total
    legendPage.drawText(`Total: ${totalStitches.toLocaleString()} stitches`, {
      x: margin,
      y: yPos - 10,
      size: 10,
      font: fontBold,
      color: rgb(0.3, 0.3, 0.3),
    });

    // Belt repeat note
    if (metadata.templateId === 'belt') {
      legendPage.drawText('Note: This is a repeating tile. Tile ~7 times across the belt length.', {
        x: margin,
        y: yPos - 30,
        size: 9,
        font,
        color: rgb(0.3, 0.2, 0.6),
      });
    }

    const pdfBytes = await pdf.save();
    const blob = new Blob([pdfBytes], { type: 'application/pdf' });
    const link = document.createElement('a');
    link.download = `needlepix-${metadata.templateId}-${Date.now()}.pdf`;
    link.href = URL.createObjectURL(blob);
    link.click();
    URL.revokeObjectURL(link.href);
  }

  return (
    <div className="flex gap-3">
      <button
        onClick={handlePngExport}
        className="flex-1 py-2.5 bg-white border border-gray-300 text-gray-700 font-medium rounded-lg hover:bg-gray-50 transition-colors text-sm cursor-pointer"
      >
        Download PNG
      </button>
      <button
        onClick={handlePdfExport}
        className="flex-1 py-2.5 bg-indigo-500 text-white font-medium rounded-lg hover:bg-indigo-600 transition-colors text-sm cursor-pointer"
      >
        Download PDF
      </button>
    </div>
  );
}

function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? { r: parseInt(result[1], 16), g: parseInt(result[2], 16), b: parseInt(result[3], 16) }
    : { r: 255, g: 255, b: 255 };
}
