import { useEffect, useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { toast } from 'sonner';
import { Loader2, Copy, Download, Code, Search } from 'lucide-react';
import SEO from '@/components/SEO';
import { useScriptLibrary, ScriptCatalogItem } from '@/hooks/useScriptLibrary';
import { CodeViewer } from '@/components/Code/CodeViewer';

export default function Library() {
  const { ready, catalog, categories, getCode } = useScriptLibrary();
  const [selected, setSelected] = useState<ScriptCatalogItem | null>(null);
  const [code, setCode] = useState<string>('');
  const [language, setLanguage] = useState<string>('python');
  const [query, setQuery] = useState('');
  const loading = !ready;

  const [activeCat, setActiveCat] = useState<string>('');
  
  useEffect(() => {
    if (!activeCat && categories.length) setActiveCat(categories[0]);
  }, [categories, activeCat]);

  const filtered = useMemo(() => {
    const byCat = activeCat ? catalog.filter(c => c.category === activeCat) : catalog;
    if (!query) return byCat;
    const q = query.toLowerCase();
    return byCat.filter(c =>
      c.name.toLowerCase().includes(q) ||
      c.id.toLowerCase().includes(q)
    );
  }, [catalog, activeCat, query]);

  const loadCode = async (item: ScriptCatalogItem) => {
    setCode('');
    setSelected(item);
    if (!item.has_code) {
      toast.info('Este script no expone código en el servidor (modo demo)');
      return;
    }
    try {
      const scriptCode = getCode(item);
      setCode(scriptCode.content);
      setLanguage(scriptCode.language);
    } catch (e) {
      toast.error('No se pudo cargar el código del script');
    }
  };

  const copyCode = async () => {
    try {
      await navigator.clipboard.writeText(code);
      toast.success('Código copiado al portapapeles');
    } catch {
      toast.error('No se pudo copiar');
    }
  };

  const downloadCode = () => {
    if (!selected) return;
    const blob = new Blob([code], { type: 'text/x-python' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${selected.id}.py`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="container mx-auto px-6 py-10">
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-white">Biblioteca de Scripts</h1>
        <p className="text-sm text-muted-foreground mt-1">Explora y estudia el código de todas las herramientas</p>
      </header>

      {/* Search and categories */}
      <div className="flex flex-col md:flex-row md:items-center gap-3 mb-6">
        <div className="relative w-full md:w-1/2">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Buscar por nombre, autor o descripción"
            className="pl-9"
          />
        </div>
        <div className="flex gap-2 overflow-x-auto">
          <Button variant={activeCat === '' ? 'default' : 'secondary'} size="sm" onClick={() => setActiveCat('')}>Todas</Button>
          {categories.map(cat => (
            <Button key={cat} variant={activeCat === cat ? 'default' : 'secondary'} size="sm" onClick={() => setActiveCat(cat)}>
              {cat.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scripts list */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Code className="w-5 h-5" /> Scripts</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center gap-2 text-muted-foreground"><Loader2 className="w-4 h-4 animate-spin" /> Cargando...</div>
            ) : (
              <ScrollArea className="h-[60vh] pr-2">
                <div className="space-y-2">
                  {filtered.map(item => (
                    <button
                      key={`${item.category}-${item.id}`}
                      onClick={() => loadCode(item)}
                      className={`w-full text-left p-3 rounded-md border transition-colors ${selected?.id === item.id ? 'bg-accent' : 'hover:bg-muted'}`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{item.name}</span>
                        <Badge variant="secondary" className="text-xs">{item.category}</Badge>
                      </div>
                       <p className="text-xs text-muted-foreground line-clamp-2 mt-1">{item.id.replace(/_/g, ' ')}</p>
                       <div className="flex items-center gap-2 mt-2">
                         <Badge variant="outline" className="text-[10px]">{item.ext}</Badge>
                         {item.has_code ? (
                           <Badge className="text-[10px]">Código</Badge>
                         ) : (
                           <Badge variant="secondary" className="text-[10px]">Sin código</Badge>
                         )}
                       </div>
                    </button>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Code viewer */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>{selected?.name || 'Selecciona un script'}</CardTitle>
              {selected && (
                <p className="text-xs text-muted-foreground mt-1">Archivo: {selected.id}.{selected.ext}</p>
              )}
            </div>
            <div className="flex gap-2">
              <Button variant="secondary" size="sm" onClick={copyCode} disabled={!code}><Copy className="w-4 h-4 mr-1" /> Copiar</Button>
              <Button variant="default" size="sm" onClick={downloadCode} disabled={!code}><Download className="w-4 h-4 mr-1" /> Descargar</Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border bg-muted/50">
              <pre className="p-4 overflow-auto max-h-[60vh]"><code>{code || 'Selecciona un script para ver su código fuente...'}</code></pre>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Canonical (SPA approximation) */}
      <link rel="canonical" href={window.location.origin + '/library'} />
    </div>
  );
}
