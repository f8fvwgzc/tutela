import { useEffect, useRef, useState } from "react";

/**
 * A secret shown once: in this component's state only, gone when the
 * person closes it or leaves the page. It is never stored or sent again.
 */
export function OnceSecret(props: { label: string; secret: string; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return (
    <div className="c-secret" role="alert" tabIndex={-1} ref={ref}>
      <p>
        <strong>{props.label}</strong> This is the only time it is shown. Store it in your secret
        store now.
      </p>
      <code className="c-mono c-secret-value">{props.secret}</code>
      <div className="c-row">
        <button
          type="button"
          className="c-button"
          onClick={() => {
            navigator.clipboard?.writeText(props.secret).then(
              () => setCopied(true),
              () => setCopied(false),
            );
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
        <button type="button" className="c-button c-primary" onClick={props.onClose}>
          I have stored it
        </button>
      </div>
    </div>
  );
}
