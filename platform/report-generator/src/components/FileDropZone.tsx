import { useState, useCallback } from "react";
import { Upload, FileText } from "lucide-react";
import type { ExportData } from "../types";
import { parseExport } from "../utils/parse";

interface Props {
  onDataLoad: (data: ExportData) => void;
}

export default function FileDropZone({ onDataLoad }: Props) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parseFile = useCallback(
    (file: File) => {
      setError(null);
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const text = e.target?.result as string;
          const lines = text.trim().split("\n");
          const data = parseExport(lines);
          const total = data.scans.length + data.httpRecords.length + data.findings.length + data.modules.length;
          if (total === 0) throw new Error("No valid records found in file");
          onDataLoad(data);
        } catch (err) {
          setError(`Failed to parse: ${err instanceof Error ? err.message : "Unknown error"}`);
        }
      };
      reader.readAsText(file);
    },
    [onDataLoad]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) parseFile(file);
    },
    [parseFile]
  );

  const onFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) parseFile(file);
    },
    [parseFile]
  );

  return (
    <div className="max-w-lg mx-auto py-24 px-6">
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        className={`border-2 border-dashed rounded-lg p-14 text-center transition-all cursor-pointer ${
          isDragging ? "border-terracotta bg-terracotta/5" : "border-warm-border"
        }`}
        onClick={() => document.getElementById("file-input")?.click()}
      >
        <div className="flex justify-center mb-4">
          {isDragging ? (
            <FileText size={36} className="text-terracotta" />
          ) : (
            <Upload size={36} className="text-text-muted" />
          )}
        </div>
        <p className="font-serif text-xl font-bold text-charcoal mb-2">
          {isDragging ? "Drop your file" : "No Data Available"}
        </p>
        <p className="text-sm text-text-muted font-sans">
          Drop a Vigolium export (.jsonl) here, or click to browse
        </p>
        <p className="text-xs text-text-muted font-sans mt-2">
          Use <code className="bg-cream-dark px-1.5 py-0.5 rounded text-charcoal-light">vigolium export -o report.jsonl</code> to generate
        </p>
        {error && (
          <p className="mt-3 text-sm text-rose font-sans">{error}</p>
        )}
        <input
          id="file-input"
          type="file"
          accept=".jsonl,.json"
          onChange={onFileInput}
          className="hidden"
        />
      </div>
    </div>
  );
}
