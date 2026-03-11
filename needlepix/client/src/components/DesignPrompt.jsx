import { useState } from 'react';

const STYLE_OPTIONS = ['Traditional', 'Preppy', 'Modern', 'Geometric'];

const EXAMPLE_PROMPTS = [
  'Golf bag with crossed clubs',
  'Labrador retriever face',
  'Navy and white anchors',
  'Classic argyle pattern',
  'Monogram letter A with floral border',
];

export default function DesignPrompt({ canvasInfo, onGenerate, onBack }) {
  const [prompt, setPrompt] = useState('');
  const [numColors, setNumColors] = useState(8);
  const [style, setStyle] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleGenerate() {
    if (!prompt.trim()) return;

    setLoading(true);
    setError(null);

    const fullPrompt = style ? `${prompt} (${style.toLowerCase()} style)` : prompt;

    try {
      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: fullPrompt,
          templateId: canvasInfo.template.id,
          stitchCount: canvasInfo.stitchCount,
          numColors,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.message || 'Generation failed');
      }

      const data = await res.json();
      onGenerate(data, fullPrompt);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <button onClick={onBack} className="text-sm text-gray-400 hover:text-gray-600 mb-4 cursor-pointer">
        &larr; Back to canvas selection
      </button>

      <h2 className="text-2xl font-bold text-gray-800 mb-2">Describe Your Design</h2>
      <p className="text-gray-500 mb-1 text-sm">
        {canvasInfo.template.name} • {canvasInfo.cols} × {canvasInfo.rows} stitches • {canvasInfo.stitchCount}-count
      </p>
      <p className="text-gray-400 mb-6 text-xs">
        {canvasInfo.totalStitches.toLocaleString()} total stitches
        {canvasInfo.template.repeatingPattern && ' (repeating tile)'}
      </p>

      <div className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">Design Prompt</label>
          <textarea
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            placeholder="e.g., golden retriever face with navy border"
            className="w-full h-28 p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent text-sm"
          />
          <div className="flex flex-wrap gap-2 mt-2">
            {EXAMPLE_PROMPTS.map((ex) => (
              <button
                key={ex}
                onClick={() => setPrompt(ex)}
                className="text-xs px-2 py-1 bg-gray-100 text-gray-500 rounded-full hover:bg-indigo-100 hover:text-indigo-600 transition-colors cursor-pointer"
              >
                {ex}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Number of Colors: <span className="text-indigo-500">{numColors}</span>
          </label>
          <input
            type="range"
            min="4"
            max="15"
            value={numColors}
            onChange={(e) => setNumColors(Number(e.target.value))}
            className="w-full accent-indigo-500"
          />
          <div className="flex justify-between text-xs text-gray-400">
            <span>4 (simple)</span>
            <span>15 (detailed)</span>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">Style (optional)</label>
          <div className="flex gap-2">
            {STYLE_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => setStyle(style === s ? null : s)}
                className={`px-3 py-1.5 rounded-lg text-sm transition-all cursor-pointer ${
                  style === s
                    ? 'bg-indigo-500 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 p-3 rounded-lg text-sm">
            {error}
          </div>
        )}

        <button
          onClick={handleGenerate}
          disabled={!prompt.trim() || loading}
          className={`w-full py-3 font-semibold rounded-lg transition-all cursor-pointer ${
            loading
              ? 'bg-indigo-300 text-white'
              : 'bg-indigo-500 text-white hover:bg-indigo-600 disabled:bg-gray-300 disabled:cursor-not-allowed'
          }`}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Generating pattern...
            </span>
          ) : (
            'Generate Pattern'
          )}
        </button>
      </div>
    </div>
  );
}
