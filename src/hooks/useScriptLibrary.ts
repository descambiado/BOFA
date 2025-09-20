import { useEffect, useMemo, useState } from 'react';

export interface ScriptCatalogItem {
  id: string;            // slug without extension
  name: string;          // display name
  category: string;      // top-level folder under scripts/
  path: string;          // full relative path from project root
  ext: string;           // file extension
  has_code: boolean;     // always true for local files
}

export interface ScriptCode {
  filename: string;
  language: string;
  content: string;
  lines: number;
  size: number;
}

const EXT_TO_LANG: Record<string, string> = {
  py: 'python',
  sh: 'bash',
  yaml: 'yaml',
  yml: 'yaml',
  md: 'markdown',
  ts: 'typescript',
  tsx: 'tsx',
  js: 'javascript',
};

// Vite supports import.meta.glob with { as: 'raw', eager: true }
// We'll define two patterns to maximize compatibility depending on build root
const globsA = import.meta.glob('/scripts/**/*', { as: 'raw', eager: true }) as Record<string, string>;
const globsB = import.meta.glob('../../scripts/**/*', { as: 'raw', eager: true }) as Record<string, string>;
const RAW_FILES: Record<string, string> = Object.keys(globsA).length ? globsA : globsB;

function buildCatalog(): ScriptCatalogItem[] {
  const items: ScriptCatalogItem[] = [];
  Object.keys(RAW_FILES).forEach((full) => {
    // Normalize path like /scripts/red/ghost_scanner.py
    const path = full.replace(/^\/?/, '/');
    if (!path.startsWith('/scripts/')) return;

    const parts = path.split('/');
    const category = parts[2] || 'misc';
    const filename = parts[parts.length - 1];
    const ext = (filename.split('.').pop() || '').toLowerCase();
    const base = filename.replace(/\.[^.]+$/, '');

    // Skip non-code assets if any
    if (!['py','sh','yaml','yml','md','ts','tsx','js'].includes(ext)) return;

    items.push({
      id: base,
      name: base.replace(/[_-]+/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase()),
      category,
      path,
      ext,
      has_code: true,
    });
  });
  // Stable sort by category then name
  return items.sort((a,b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
}

function getCodeFor(item: ScriptCatalogItem): ScriptCode {
  const content = RAW_FILES[item.path] || '';
  const language = EXT_TO_LANG[item.ext] || 'text';
  const lines = content ? content.split('\n').length : 0;
  const size = new Blob([content]).size;
  return {
    filename: item.path.split('/').pop() || `${item.id}.${item.ext}`,
    language,
    content,
    lines,
    size,
  };
}

export function useScriptLibrary() {
  const [catalog, setCatalog] = useState<ScriptCatalogItem[]>([]);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // Build once on mount
    const items = buildCatalog();
    setCatalog(items);
    setReady(true);
  }, []);

  const categories = useMemo(() => Array.from(new Set(catalog.map(i => i.category))), [catalog]);

  const getCode = (item: ScriptCatalogItem) => getCodeFor(item);

  return { ready, catalog, categories, getCode };
}
