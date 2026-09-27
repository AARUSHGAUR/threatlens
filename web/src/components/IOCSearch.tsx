/**
 * IOCSearch - the primary analyst entry point.
 *
 * Behaviour:
 *  - debounced server-side type detection (so detection rules and the
 *    documentation-range warning live in ONE place: the backend),
 *  - inline validation feedback with the server's hint text,
 *  - optional clickable sample catalogue for the demo walkthrough,
 *  - keyboard-first: Enter submits, Escape clears.
 */
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ApiError, type DetectionResponse, type DemoCatalogEntry } from '../api/client';
import { Alert } from './ui';

export const IocSearch = ({
  onSubmit,
  busy = false,
  initialValue = '',
  placeholder = 'Enter IP, domain, URL, hash or email…',
  showSamples = true,
  autoFocus = true,
  compact = false,
}: {
  onSubmit: (indicator: string) => void;
  busy?: boolean;
  initialValue?: string;
  placeholder?: string;
  showSamples?: boolean;
  autoFocus?: boolean;
  compact?: boolean;
}) => {
  const [value, setValue] = useState(initialValue);
  const [detection, setDetection] = useState<DetectionResponse | null>(null);
  const [checking, setChecking] = useState(false);
  const [samples, setSamples] = useState<DemoCatalogEntry[]>([]);
  const [touched, setTouched] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const abortRef = useRef<number | null>(null);

  useEffect(() => {
    if (showSamples) {
      api
        .bootstrap()
        .then((b) => setSamples(b.demoCatalog))
        .catch(() => setSamples([]));
    }
  }, [showSamples]);

  // Debounced detection. 220ms is long enough to avoid a request per keystroke
  // and short enough that the hint feels instant.
  useEffect(() => {
    const trimmed = value.trim();
    if (abortRef.current) window.clearTimeout(abortRef.current);
    if (trimmed.length < 3) {
      setDetection(null);
      setChecking(false);
      return;
    }
    setChecking(true);
    abortRef.current = window.setTimeout(() => {
      api
        .detect(trimmed)
        .then((result) => {
          setDetection(result);
          setChecking(false);
        })
        .catch(() => {
          setDetection(null);
          setChecking(false);
        });
    }, 220);
    return () => {
      if (abortRef.current) window.clearTimeout(abortRef.current);
    };
  }, [value]);

  const submit = useCallback(
    (event?: FormEvent) => {
      event?.preventDefault();
      const trimmed = value.trim();
      setTouched(true);
      if (!trimmed) return;
      onSubmit(trimmed);
    },
    [onSubmit, value],
  );

  const invalid = touched && detection !== null && !detection.valid;
  const showError = invalid && detection?.error;

  return (
    <div className="ioc-search">
      <form onSubmit={submit}>
        <div className="ioc-search-bar">
          <div className="ioc-input-wrap">
            <span className="ioc-search-icon" aria-hidden="true">
              ⌕
            </span>
            <input
              ref={inputRef}
              className={`ioc-input ${invalid ? 'invalid' : ''}`}
              type="text"
              value={value}
              autoFocus={autoFocus}
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              placeholder={placeholder}
              aria-label="Indicator of compromise"
              aria-describedby="ioc-search-help"
              onChange={(e) => setValue(e.target.value)}
              onBlur={() => setTouched(true)}
              onKeyDown={(e) => {
                if (e.key === 'Escape') {
                  setValue('');
                  setDetection(null);
                  inputRef.current?.blur();
                }
              }}
            />
            <span className="ioc-detected">
              {checking ? (
                <span className="spinner" />
              ) : detection?.detection ? (
                <span className="badge badge-accent" title={`Detected by the ${detection.detection.rule} rule`}>
                  {detection.detection.typeLabel}
                </span>
              ) : null}
            </span>
          </div>
          <button className="btn btn-primary" type="submit" disabled={busy || !value.trim()}>
            {busy ? <span className="spinner" /> : <span aria-hidden="true">⌕</span>}
            {busy ? 'Investigating' : 'Investigate IOC'}
          </button>
        </div>
      </form>

      <div id="ioc-search-help" className="mt-3 small muted">
        Supported: IPv4, IPv6, domain, http(s) URL, MD5, SHA1, SHA256, email address. Defanged indicators
        (<code className="inline-code">hxxp://evil[.]com</code>) are re-fanged automatically.
      </div>

      {showError ? (
        <div className="mt-3">
          <Alert kind="danger" title={showError.message}>
            {showError.hint ?? 'Correct the indicator and try again.'}
          </Alert>
        </div>
      ) : null}

      {detection?.valid && detection.warnings.length > 0 ? (
        <div className="mt-3 flex flex-col gap-2">
          {detection.warnings.map((w) => (
            <Alert key={w.code} kind="warning">
              <strong className="mono">{w.code}</strong> — {w.message}
            </Alert>
          ))}
        </div>
      ) : null}

      {detection?.valid && detection.isDocumentationExample ? (
        <div className="mt-3">
          <Alert kind="demo" title="Documentation range" icon="◈">
            This address is inside an RFC 5737 / RFC 3849 documentation range, which is exactly what the built-in
            demonstration dataset uses. Live providers will hold no intelligence about it.
          </Alert>
        </div>
      ) : null}

      {detection?.detection?.defanged ? (
        <div className="mt-3">
          <Alert kind="info" title="Defanged indicator detected">
            The value has been re-fanged to <code className="inline-code">{detection.detection.value}</code> before lookup.
          </Alert>
        </div>
      ) : null}

      {showSamples && samples.length > 0 ? (
        <div className="mt-4">
          <div className="section-title">Demonstration walkthrough — click to load</div>
          <div className="samples">
            {samples.map((s) => (
              <button
                key={s.value}
                type="button"
                className="sample"
                onClick={() => {
                  setValue(s.value);
                  onSubmit(s.value);
                }}
                title={s.summary}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="badge badge-neutral">{s.type.toUpperCase()}</span>
                  <span
                    className={`badge ${
                      s.expectedLevel === 'CRITICAL'
                        ? 'badge-critical'
                        : s.expectedLevel === 'HIGH'
                          ? 'badge-high'
                          : s.expectedLevel === 'MEDIUM'
                            ? 'badge-medium'
                            : 'badge-clean'
                    }`}
                  >
                    {s.expectedLevel}
                  </span>
                </div>
                <div className="sample-value">{s.value}</div>
                <div className="sample-title">{s.title}</div>
              </button>
            ))}
          </div>
          <div className="mt-3 tiny dim">
            Sample indicators use documentation IP ranges, RFC 2606 reserved domains and synthetic hashes, so no real
            infrastructure is named. <button className="btn btn-sm btn-ghost" onClick={() => navigate('/settings')}>Review provider configuration</button>
          </div>
        </div>
      ) : null}
    </div>
  );
};
