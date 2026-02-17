# Contenido de la Wiki de GitHub

Esta carpeta contiene el **contenido listo** para la Wiki del repositorio [descambiado/BOFA](https://github.com/descambiado/BOFA). Así el roadmap, estado e instalación quedan documentados y versionados en el repo.

## Cómo publicar en la Wiki de GitHub

1. En GitHub: **BOFA** → pestaña **Wiki** → **Create the first page** (o **New Page** si ya existe algo).
2. Crear estas páginas y **pegar el contenido** del archivo correspondiente:

   | Página en la Wiki | Archivo en este repo |
   |-------------------|----------------------|
   | **Home** (portada) | `wiki/Home.md` |
   | **Status** | `wiki/Status.md` |
   | **Roadmap** | `wiki/Roadmap.md` |
   | **Installation** | `wiki/Installation.md` |
   | **_Sidebar** (opcional) | `wiki/_Sidebar.md` |

3. Para **_Sidebar**: en la Wiki, crear una página llamada exactamente `_Sidebar` y pegar el contenido de `_Sidebar.md`. GitHub la usará como menú lateral.

## Alternativa: clonar el repo de la Wiki

Si ya tienes al menos una página creada en la Wiki, GitHub habilita un repositorio `wiki`:

```bash
git clone https://github.com/descambiado/BOFA.wiki.git
cd BOFA.wiki
# Copiar aquí los .md desde wiki/ (renombrar Home.md → Home.md, etc.)
git add .
git commit -m "Wiki: Home, Status, Roadmap, Installation, Sidebar"
git push origin master
```

Los nombres de archivo en la Wiki deben coincidir con los títulos de página (Home.md, Status.md, etc.).
