import { useState } from 'react';
import TemplateSelector from './components/TemplateSelector.jsx';
import DesignPrompt from './components/DesignPrompt.jsx';
import NeedlepointGrid from './components/NeedlepointGrid.jsx';
import ColorLegend from './components/ColorLegend.jsx';
import ExportPanel from './components/ExportPanel.jsx';
import { mapPaletteToDMC } from './utils/colorQuantize.js';

export default function App() {
  const [step, setStep] = useState(1);
  const [canvasInfo, setCanvasInfo] = useState(null);
  const [result, setResult] = useState(null);
  const [prompt, setPrompt] = useState('');

  function handleTemplateSelect(info) {
    setCanvasInfo(info);
    setStep(2);
  }

  function handleGenerate(data, usedPrompt) {
    // Map AI palette colors to nearest DMC colors
    const dmcPalette = mapPaletteToDMC(data.palette);
    setResult({ ...data, palette: dmcPalette });
    setPrompt(usedPrompt);
    setStep(3);
  }

  function handleRegenerate() {
    setStep(2);
  }

  function handleStartOver() {
    setStep(1);
    setCanvasInfo(null);
    setResult(null);
    setPrompt('');
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
          <button onClick={handleStartOver} className="flex items-center gap-2 cursor-pointer">
            <span className="text-2xl">🧵</span>
            <h1 className="text-xl font-bold text-gray-800">NeedlePix</h1>
          </button>
          <div className="flex items-center gap-1">
            {[1, 2, 3].map((s) => (
              <div
                key={s}
                className={`w-8 h-1 rounded-full ${s <= step ? 'bg-indigo-500' : 'bg-gray-200'}`}
              />
            ))}
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-5xl mx-auto px-4 py-8">
        {step === 1 && <TemplateSelector onSelect={handleTemplateSelect} />}

        {step === 2 && canvasInfo && (
          <DesignPrompt
            canvasInfo={canvasInfo}
            onGenerate={handleGenerate}
            onBack={() => setStep(1)}
          />
        )}

        {step === 3 && result && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-2xl font-bold text-gray-800">Your Pattern</h2>
                <p className="text-sm text-gray-400 mt-1">"{prompt}"</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleRegenerate}
                  className="px-4 py-2 text-sm bg-white border border-gray-300 text-gray-600 rounded-lg hover:bg-gray-50 cursor-pointer"
                >
                  Edit Prompt
                </button>
                <button
                  onClick={() => {
                    setResult(null);
                    setStep(2);
                  }}
                  className="px-4 py-2 text-sm bg-white border border-gray-300 text-gray-600 rounded-lg hover:bg-gray-50 cursor-pointer"
                >
                  Regenerate
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <NeedlepointGrid
                  grid={result.grid}
                  palette={result.palette}
                  metadata={result.metadata}
                />
              </div>
              <div className="space-y-6">
                <ColorLegend palette={result.palette} grid={result.grid} />
                <ExportPanel
                  grid={result.grid}
                  palette={result.palette}
                  metadata={result.metadata}
                  prompt={prompt}
                />
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="text-center py-6 text-xs text-gray-300">
        NeedlePix — AI-powered needlepoint pattern generator
      </footer>
    </div>
  );
}
