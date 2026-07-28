import { useEffect, useMemo, useState } from 'react';
import { apiService } from '@/services/api';

export interface ScriptCatalogItem {
  id: string;
  name: string;
  category: string;
  description?: string;
  author?: string;
  version?: string;
  last_updated?: string;
  usage?: string | null;
  ext: string;
  has_code: boolean;
}

export interface ScriptCode {
  filename: string;
  language: string;
  content: string;
  lines: number;
  size: number;
}

const normalizeCatalogItem = (item: Record<string, any>): ScriptCatalogItem => {
  const filename =
    (item.file_path_py as string | undefined)?.split(/[\\/]/).pop() ||
    `${item.id || 'script'}.py`;
  const ext = filename.includes('.') ? filename.split('.').pop()!.toLowerCase() : 'py';

  return {
    id: String(item.id || item.name || 'script'),
    name: String(item.name || item.id || 'Script'),
    category: String(item.category || 'misc'),
    description: item.description || '',
    author: item.author,
    version: item.version,
    last_updated: item.last_updated,
    usage: item.usage || null,
    ext,
    has_code: Boolean(item.has_code),
  };
};

export function useScriptLibrary() {
  const [catalog, setCatalog] = useState<ScriptCatalogItem[]>([]);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const loadCatalog = async () => {
      try {
        setReady(false);
        setError(null);
        const items = await apiService.getScriptCatalog();
        if (cancelled) {
          return;
        }
        setCatalog(items.map((item) => normalizeCatalogItem(item as Record<string, any>)));
      } catch (err) {
        if (cancelled) {
          return;
        }
        setCatalog([]);
        setError(err instanceof Error ? err.message : 'No se pudo cargar la biblioteca');
      } finally {
        if (!cancelled) {
          setReady(true);
        }
      }
    };

    void loadCatalog();

    return () => {
      cancelled = true;
    };
  }, []);

  const categories = useMemo(
    () => Array.from(new Set(catalog.map((item) => item.category))),
    [catalog],
  );

  const getCode = async (item: ScriptCatalogItem): Promise<ScriptCode> => {
    return apiService.getScriptCode(item.category, item.id);
  };

  return { ready, catalog, categories, getCode, error };
}
