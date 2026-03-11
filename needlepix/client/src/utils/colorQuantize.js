import chroma from 'chroma-js';
import dmcColors from '../data/dmc-colors.js';

// Pre-compute Lab values for all DMC colors
const dmcLab = dmcColors.map((c) => ({
  ...c,
  lab: chroma(c.hex).lab(),
}));

function labDistance(lab1, lab2) {
  const dL = lab1[0] - lab2[0];
  const da = lab1[1] - lab2[1];
  const db = lab1[2] - lab2[2];
  return Math.sqrt(dL * dL + da * da + db * db);
}

export function findNearestDMC(hexColor) {
  const targetLab = chroma(hexColor).lab();
  let bestMatch = dmcLab[0];
  let bestDist = Infinity;

  for (const dmc of dmcLab) {
    const dist = labDistance(targetLab, dmc.lab);
    if (dist < bestDist) {
      bestDist = dist;
      bestMatch = dmc;
    }
  }

  return {
    dmc: bestMatch.dmc,
    name: bestMatch.name,
    hex: bestMatch.hex,
    distance: bestDist,
  };
}

export function mapPaletteToDMC(palette) {
  return palette.map((color) => {
    const nearest = findNearestDMC(color.hex);
    return {
      ...color,
      dmc: nearest.dmc,
      dmcName: nearest.name,
      dmcHex: nearest.hex,
      distance: nearest.distance,
    };
  });
}
