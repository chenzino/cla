const systemPrompt = `You are a needlepoint pattern designer. You generate pixel-art stitch patterns as precise JSON grids.

You think like an experienced needlepoint artist:
- Bold, clean shapes with clear outlines
- Centered compositions that use the full canvas
- Limited, harmonious color palettes
- Backgrounds that frame the subject without competing with it
- Classic needlepoint motifs: clean geometry, clear silhouettes

You ONLY return valid JSON. No preamble, no explanation, no markdown fences.`;

function buildUserPrompt({ prompt, cols, rows, numColors, templateName, isRepeating }) {
  let text = `Design a needlepoint pattern for the following:

Subject: "${prompt}"
Canvas: ${cols} stitches wide × ${rows} stitches tall
Colors: exactly ${numColors} (including background)
Template: ${templateName}

Return ONLY this JSON structure:
{
  "grid": [[colorIndex, ...], ...],
  "palette": [{"hex": "#RRGGBB", "name": "descriptive color name"}, ...]
}

Rules:
- grid must be exactly ${rows} arrays, each with exactly ${cols} integers
- integers are 0-based indices into palette array
- palette must have exactly ${numColors} entries
- hex values must be valid 6-digit HTML hex colors
- Color 0 should be the background color
- Design should be centered with the subject filling 60-80% of the canvas`;

  if (cols > 60 || rows > 60) {
    text += `\n- Prioritize bold, simple shapes over fine detail. Think cross-stitch silhouette, not photorealism.`;
  }

  if (isRepeating) {
    text += `\n- The design will repeat horizontally. Ensure left and right edges are compatible for seamless tiling.`;
  }

  return text;
}

const retryPrompt = `Your previous response was not valid JSON. Return ONLY the JSON object, starting with \`{\`. No markdown fences, no explanation.`;

module.exports = { systemPrompt, buildUserPrompt, retryPrompt };
