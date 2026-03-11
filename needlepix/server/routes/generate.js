const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const { systemPrompt, buildUserPrompt, retryPrompt } = require('../prompts/gridPrompt');

const router = express.Router();

const client = new Anthropic();

function validateGrid(grid, palette, rows, cols, numColors) {
  if (!Array.isArray(grid) || grid.length !== rows) {
    return `Grid must have exactly ${rows} rows, got ${grid?.length}`;
  }
  for (let r = 0; r < grid.length; r++) {
    if (!Array.isArray(grid[r]) || grid[r].length !== cols) {
      return `Row ${r} must have exactly ${cols} columns, got ${grid[r]?.length}`;
    }
    for (let c = 0; c < grid[r].length; c++) {
      const val = grid[r][c];
      if (!Number.isInteger(val) || val < 0 || val >= numColors) {
        // Clamp out-of-bounds indices instead of failing
        grid[r][c] = Math.max(0, Math.min(val, numColors - 1));
      }
    }
  }
  if (!Array.isArray(palette) || palette.length !== numColors) {
    return `Palette must have exactly ${numColors} entries, got ${palette?.length}`;
  }
  return null;
}

async function callClaude(userPrompt, maxTokens) {
  const response = await client.messages.create({
    model: 'claude-sonnet-4-5-20250514',
    max_tokens: maxTokens,
    temperature: 0.7,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }],
  });

  const text = response.content[0].text.trim();
  return text;
}

function parseJSON(text) {
  // Try direct parse first
  try {
    return JSON.parse(text);
  } catch (_) {
    // Try extracting JSON from potential markdown fences
    const match = text.match(/\{[\s\S]*\}/);
    if (match) {
      return JSON.parse(match[0]);
    }
    throw new Error('Could not parse JSON from response');
  }
}

router.post('/', async (req, res) => {
  try {
    const { prompt, templateId, stitchCount, numColors } = req.body;

    if (!prompt || !templateId || !stitchCount || !numColors) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'prompt, templateId, stitchCount, and numColors are required',
      });
    }

    // Import templates to get dimensions
    const templates = require('../../client/src/data/templates');
    const template = templates.find((t) => t.id === templateId);
    if (!template) {
      return res.status(400).json({ error: 'Invalid template', message: `Template "${templateId}" not found` });
    }

    const effectiveWidth = template.repeatingPattern ? template.tileWidthInches : template.widthInches;
    const cols = Math.min(Math.round(effectiveWidth * stitchCount), 120);
    const rows = Math.round(template.heightInches * stitchCount);

    const maxTokens = Math.max(12000, Math.min(cols * rows * 3, 64000));

    const userPrompt = buildUserPrompt({
      prompt,
      cols,
      rows,
      numColors,
      templateName: template.name,
      isRepeating: template.repeatingPattern,
    });

    let text = await callClaude(userPrompt, maxTokens);
    let parsed;

    try {
      parsed = parseJSON(text);
    } catch (_) {
      // Retry once with stricter prompt
      const retryMessages = [
        { role: 'user', content: userPrompt },
        { role: 'assistant', content: text },
        { role: 'user', content: retryPrompt },
      ];

      const retryResponse = await client.messages.create({
        model: 'claude-sonnet-4-5-20250514',
        max_tokens: maxTokens,
        temperature: 0.5,
        system: systemPrompt,
        messages: retryMessages,
      });

      text = retryResponse.content[0].text.trim();
      parsed = parseJSON(text);
    }

    const { grid, palette } = parsed;

    const validationError = validateGrid(grid, palette, rows, cols, numColors);
    if (validationError) {
      return res.status(502).json({ error: 'Generation failed', message: validationError });
    }

    res.json({
      grid,
      palette: palette.map((p, i) => ({
        index: i,
        hex: p.hex,
        name: p.name,
      })),
      metadata: {
        cols,
        rows,
        totalStitches: cols * rows,
        templateId,
        prompt,
      },
    });
  } catch (err) {
    console.error('Generate error:', err);

    if (err.status === 429) {
      return res.status(429).json({
        error: 'Rate limited',
        message: 'Too many requests. Please wait a moment and try again.',
      });
    }

    res.status(500).json({
      error: 'Generation failed',
      message: err.message || 'An unexpected error occurred',
    });
  }
});

module.exports = router;
