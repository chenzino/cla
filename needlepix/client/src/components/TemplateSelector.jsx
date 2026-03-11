import { useState } from 'react';
import templates from '../data/templates.js';

export default function TemplateSelector({ onSelect }) {
  const [selectedId, setSelectedId] = useState(null);
  const [stitchCount, setStitchCount] = useState(null);

  const selected = templates.find((t) => t.id === selectedId);

  function handleTemplateClick(template) {
    setSelectedId(template.id);
    setStitchCount(template.defaultCount);
  }

  function handleContinue() {
    if (!selected || !stitchCount) return;
    const effectiveWidth = selected.repeatingPattern ? selected.tileWidthInches : selected.widthInches;
    const cols = Math.min(Math.round(effectiveWidth * stitchCount), 120);
    const rows = Math.round(selected.heightInches * stitchCount);
    onSelect({
      template: selected,
      stitchCount,
      cols,
      rows,
      totalStitches: cols * rows,
    });
  }

  return (
    <div className="max-w-3xl mx-auto">
      <h2 className="text-2xl font-bold text-gray-800 mb-2">Choose Your Canvas</h2>
      <p className="text-gray-500 mb-6">Select a canvas type and stitch count to get started.</p>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 mb-6">
        {templates.map((t) => (
          <button
            key={t.id}
            onClick={() => handleTemplateClick(t)}
            className={`p-4 rounded-xl border-2 text-left transition-all cursor-pointer ${
              selectedId === t.id
                ? 'border-indigo-500 bg-indigo-50 shadow-md'
                : 'border-gray-200 bg-white hover:border-gray-300 hover:shadow-sm'
            }`}
          >
            <div className="text-3xl mb-2">{t.icon}</div>
            <div className="font-semibold text-gray-800 text-sm">{t.name}</div>
            <div className="text-xs text-gray-400 mt-1">
              {t.repeatingPattern
                ? `${t.tileWidthInches}" × ${t.heightInches}" tile`
                : `${t.widthInches}" × ${t.heightInches}"`}
            </div>
          </button>
        ))}
      </div>

      {selected && (
        <div className="bg-gray-50 rounded-xl p-5 border border-gray-200">
          <div className="flex items-center gap-4 mb-4">
            <span className="text-sm font-medium text-gray-600">Stitch Count:</span>
            <div className="flex gap-2">
              {selected.countOptions.map((count) => (
                <button
                  key={count}
                  onClick={() => setStitchCount(count)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer ${
                    stitchCount === count
                      ? 'bg-indigo-500 text-white shadow-sm'
                      : 'bg-white text-gray-600 border border-gray-300 hover:bg-gray-100'
                  }`}
                >
                  {count}-count
                </button>
              ))}
            </div>
          </div>

          {stitchCount && (
            <>
              <div className="text-sm text-gray-500 mb-4">
                {(() => {
                  const effectiveWidth = selected.repeatingPattern ? selected.tileWidthInches : selected.widthInches;
                  const cols = Math.min(Math.round(effectiveWidth * stitchCount), 120);
                  const rows = Math.round(selected.heightInches * stitchCount);
                  return (
                    <>
                      Grid: <span className="font-semibold text-gray-700">{cols} × {rows}</span> stitches
                      {' '}({(cols * rows).toLocaleString()} total)
                      {selected.repeatingPattern && (
                        <span className="text-indigo-500 ml-2">• Repeating tile</span>
                      )}
                    </>
                  );
                })()}
              </div>
              {selected.notes && <p className="text-xs text-gray-400 mb-4">{selected.notes}</p>}
              <button
                onClick={handleContinue}
                className="w-full py-3 bg-indigo-500 text-white font-semibold rounded-lg hover:bg-indigo-600 transition-colors cursor-pointer"
              >
                Continue
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
