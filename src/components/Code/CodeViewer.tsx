import React from 'react';
// Work around TS JSX typing differences by aliasing as any
import HighlightRaw, { Language, themes } from 'prism-react-renderer';

const Highlight: any = HighlightRaw as any;

interface Props {
  code: string;
  language: string;
  className?: string;
}

export const CodeViewer: React.FC<Props> = ({ code, language, className }) => {
  const lang = (language as Language) || 'python';
  return (
    <div className={`rounded-md border bg-muted/50 overflow-auto ${className || ''}`}>
      <Highlight theme={themes.nightOwl} code={code} language={lang}>
        {({ className: cn, style, tokens, getLineProps, getTokenProps }) => (
          <pre className={`${cn} p-4 text-sm`} style={style}>
            {tokens.map((line: any, i: number) => (
              <div key={i} {...getLineProps({ line, key: i })}>
                {line.map((token: any, key: number) => (
                  <span key={key} {...getTokenProps({ token, key })} />
                ))}
              </div>
            ))}
          </pre>
        )}
      </Highlight>
    </div>
  );
};
