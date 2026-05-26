import { useEffect, useMemo, useState } from 'react';
import { Button } from '@/components/UI/button';
import { Badge } from '@/components/UI/badge';
import { Input } from '@/components/UI/input';
import { ScrollArea } from '@/components/UI/scroll-area';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/UI/card';
import { toast } from 'sonner';
import { Loader2, Copy, Download, Code, Search, AlertTriangle } from 'lucide-react';
import { useScriptLibrary, ScriptCatalogItem } from '@/hooks/useScriptLibrary';
import { CodeViewer } from '@/components/Code/CodeViewer';

export default function Library() {
  const { ready, catalog, categories, getCode, error } = useScriptLibrary();
  const [selected, setSelected] = useState<ScriptCatalogItem | null>(null);
  const [code, setCode] = useState<string>('');
  const [language, setLanguage] = useState<string>('python');
  const [query, setQuery] = useState('');
  const [activeCat, setActiveCat] = useState<string>('');
  const [isLoadingCode, setIsLoadingCode] = useState(false);
  const loading = !ready;

  useEffect(() => {
    if (!activeCat && categories.length) {
      setActiveCat(categories[0]);
    }
  }, [categories, activeCat]);

  const filtered = useMemo(() => {
    const byCat = activeCat ? catalog.filter((item) => item.category === activeCat) : catalog;
    if (!query) {
      return byCat;
    }

    const lowerQuery = query.toLowerCase();
    return byCat.filter(
      (item) =>
        item.name.toLowerCase().includes(lowerQuery) ||
        item.id.toLowerCase().includes(lowerQuery) ||
        item.description?.toLowerCase().includes(lowerQuery),
    );
  }, [catalog, activeCat, query]);

  const loadCode = async (item: ScriptCatalogItem) => {
    setCode('');
    setSelected(item);

    if (!item.has_code) {
      setLanguage('text');
      toast.info('Este script no expone codigo en el servidor en este modo');
      return;
    }

    try {
      setIsLoadingCode(true);
      const scriptCode = await getCode(item);
      setCode(scriptCode.content);
      setLanguage(scriptCode.language);
    } catch {
      setCode('');
      toast.error('No se pudo cargar el codigo del script');
    } finally {
      setIsLoadingCode(false);
    }
  };

  const copyCode = async () => {
    try {
      await navigator.clipboard.writeText(code);
      toast.success('Codigo copiado al portapapeles');
    } catch {
      toast.error('No se pudo copiar');
    }
  };

  const downloadCode = () => {
    if (!selected || !code) {
      return;
    }

    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
    const anchor = document.createElement('a');
    anchor.href = URL.createObjectURL(blob);
    anchor.download = `${selected.id}.${selected.ext}`;
    anchor.click();
    URL.revokeObjectURL(anchor.href);
  };

  return (
    <div className="container mx-auto px-6 py-10">
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-white">Biblioteca de Scripts</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Explora el catalogo que BOFA expone desde el runtime y revisa el codigo cuando esta disponible.
        </p>
      </header>

      {error && (
        <div className="mb-6 flex items-start gap-3 rounded-xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <p>{error}</p>
        </div>
      )}

      <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center">
        <div className="relative w-full md:w-1/2">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Buscar por nombre, id o descripcion"
            className="pl-9"
          />
        </div>
        <div className="flex gap-2 overflow-x-auto">
          <Button
            variant={activeCat === '' ? 'default' : 'secondary'}
            size="sm"
            onClick={() => setActiveCat('')}
          >
            Todas
          </Button>
          {categories.map((category) => (
            <Button
              key={category}
              variant={activeCat === category ? 'default' : 'secondary'}
              size="sm"
              onClick={() => setActiveCat(category)}
            >
              {category.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code className="h-5 w-5" />
              Scripts
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Cargando catalogo...
              </div>
            ) : (
              <ScrollArea className="h-[60vh] pr-2">
                <div className="space-y-2">
                  {filtered.map((item) => (
                    <button
                      key={`${item.category}-${item.id}`}
                      onClick={() => void loadCode(item)}
                      className={`w-full rounded-md border p-3 text-left transition-colors ${
                        selected?.id === item.id ? 'bg-accent' : 'hover:bg-muted'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium">{item.name}</span>
                        <Badge variant="secondary" className="text-xs">
                          {item.category}
                        </Badge>
                      </div>
                      <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">
                        {item.description || item.id.replace(/_/g, ' ')}
                      </p>
                      <div className="mt-2 flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px]">
                          {item.ext}
                        </Badge>
                        {item.has_code ? (
                          <Badge className="text-[10px]">Codigo</Badge>
                        ) : (
                          <Badge variant="secondary" className="text-[10px]">
                            Solo catalogo
                          </Badge>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between gap-4">
            <div>
              <CardTitle>{selected?.name || 'Selecciona un script'}</CardTitle>
              {selected && (
                <p className="mt-1 text-xs text-muted-foreground">
                  Archivo: {selected.id}.{selected.ext}
                </p>
              )}
            </div>
            <div className="flex gap-2">
              <Button variant="secondary" size="sm" onClick={copyCode} disabled={!code || isLoadingCode}>
                <Copy className="mr-1 h-4 w-4" />
                Copiar
              </Button>
              <Button variant="default" size="sm" onClick={downloadCode} disabled={!code || isLoadingCode}>
                <Download className="mr-1 h-4 w-4" />
                Descargar
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {isLoadingCode ? (
              <div className="flex min-h-[60vh] items-center justify-center rounded-md border bg-muted/50 text-muted-foreground">
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Cargando codigo del script...
              </div>
            ) : code ? (
              <CodeViewer code={code} language={language} className="max-h-[60vh]" />
            ) : (
              <div className="flex min-h-[60vh] items-center justify-center rounded-md border bg-muted/50 p-6 text-sm text-muted-foreground">
                Selecciona un script para ver su codigo fuente o su disponibilidad en el runtime.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <link rel="canonical" href={window.location.origin + '/library'} />
    </div>
  );
}
