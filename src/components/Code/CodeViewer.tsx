import React from 'react';
import { Highlight, Language, themes } from 'prism-react-renderer';

interface Props {
  code: string;
  language: string;
  className?: string;
}

export const CodeViewer: React.FC<Props> = ({ code, language, className }) => {
  const normalizedLanguage = (language as Language) || 'python';

  return (
    <div className={`overflow-auto rounded-md border bg-muted/50 ${className || ''}`}>
      <Highlight theme={themes.nightOwl} code={code} language={normalizedLanguage}>
        {({ className: highlightClassName, style, tokens, getLineProps, getTokenProps }) => (
          <pre className={`${highlightClassName} p-4 text-sm`} style={style}>
            {tokens.map((line, lineIndex) => (
              <div key={lineIndex} {...getLineProps({ line, key: lineIndex })}>
                {line.map((token, tokenIndex) => (
                  <span key={tokenIndex} {...getTokenProps({ token, key: tokenIndex })} />
                ))}
              </div>
            ))}
          </pre>
        )}
      </Highlight>
    </div>
  );
};
