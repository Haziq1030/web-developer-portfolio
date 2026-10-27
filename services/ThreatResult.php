<?php
/**
 * The single normalized shape every provider returns.
 *
 * The point of this class is to keep "I could not check" distinct from "it is
 * clean". The old engine collapsed both into Safe, which is the worst possible
 * default for a security tool. There are four verdicts and only one of them
 * means the indicator was actually looked up and came back clean.
 */
class ThreatResult
{
    public const MALICIOUS  = 'malicious';   // providers positively flagged it
    public const SUSPICIOUS = 'suspicious';  // weak or partial signal
    public const CLEAN      = 'clean';       // checked, nothing found
    public const UNKNOWN    = 'unknown';     // never seen / not checked
    public const ERROR      = 'error';       // lookup failed — NOT a verdict

    public string $provider;
    public string $verdict = self::UNKNOWN;
    public ?float $score = null;      // 0-100, provider-specific meaning
    public string $summary = '';
    public array  $detail = [];
    public bool   $cached = false;
    public ?string $fetchedAt = null;
    public string $error = '';

    public function __construct(string $provider)
    {
        $this->provider = $provider;
    }

    public static function error(string $provider, string $message): self
    {
        $r = new self($provider);
        $r->verdict = self::ERROR;
        $r->error = $message;
        $r->summary = $message;
        return $r;
    }

    public function isConclusive(): bool
    {
        return $this->verdict !== self::ERROR && $this->verdict !== self::UNKNOWN;
    }

    /**
     * The name shown to students.
     *
     * $this->provider stays the real vendor name throughout — logs, the
     * database and the admin diagnostics all depend on it. Only the rendering
     * layer swaps in a neutral label, so turning SHOW_PROVIDER_NAMES back on
     * changes the display and nothing else.
     */
    public function displayName(): string
    {
        if (SHOW_PROVIDER_NAMES) {
            return $this->provider;
        }
        return PROVIDER_LABELS[$this->provider] ?? 'Threat Intelligence';
    }

    public function badgeClass(): string
    {
        switch ($this->verdict) {
            case self::MALICIOUS:  return 'text-bg-danger';
            case self::SUSPICIOUS: return 'text-bg-warning';
            case self::CLEAN:      return 'text-bg-success';
            case self::ERROR:      return 'text-bg-dark';
            default:               return 'text-bg-secondary';
        }
    }

    public function label(): string
    {
        switch ($this->verdict) {
            case self::MALICIOUS:  return 'Malicious';
            case self::SUSPICIOUS: return 'Suspicious';
            case self::CLEAN:      return 'Clean';
            case self::ERROR:      return 'Lookup failed';
            default:               return 'Unknown';
        }
    }

    /**
     * Combine several provider results into one headline verdict.
     *
     * Rules, in order:
     *   - any provider says malicious              -> Malicious
     *   - any provider says suspicious             -> Suspicious
     *   - at least one provider says clean         -> Clean
     *   - nobody could tell us anything            -> Unknown / Error
     *
     * Note what this deliberately does NOT do: invent a combined percentage.
     * Each provider's own number is shown next to its own name. A blended
     * "99.90%" would be a figure you cannot defend when someone asks how it
     * was calculated.
     *
     * @param ThreatResult[] $results
     */
    public static function aggregate(array $results): array
    {
        $conclusive = array_filter($results, static fn(ThreatResult $r) => $r->isConclusive());
        $providerScores = array_filter(array_map(static fn(ThreatResult $r) => $r->score, $results), static fn($score) => $score !== null);

        $verdict = self::UNKNOWN;
        foreach ($results as $r) {
            if ($r->verdict === self::MALICIOUS) { $verdict = self::MALICIOUS; break; }
            if ($r->verdict === self::SUSPICIOUS) { $verdict = self::SUSPICIOUS; }
        }
        if ($verdict === self::UNKNOWN && count($conclusive) > 0) {
            foreach ($conclusive as $r) {
                if ($r->verdict === self::CLEAN) { $verdict = self::CLEAN; break; }
            }
        }
        if (count($conclusive) === 0) {
            $allErrored = count($results) > 0
                && count(array_filter($results, static fn(ThreatResult $r) => $r->verdict === self::ERROR)) === count($results);
            $verdict = $allErrored ? self::ERROR : self::UNKNOWN;
        }

        $riskScore = $verdict === self::CLEAN ? 0 : null;
        if ($verdict === self::MALICIOUS || $verdict === self::SUSPICIOUS) {
            $riskScore = $providerScores ? (int) ceil(max($providerScores)) : 1;
            $riskScore = max(1, min(100, $riskScore));
        }

        return [
            'verdict'           => $verdict,
            'providers_queried' => count($results),
            'providers_usable'  => count($conclusive),
            'risk_score'       => $riskScore,
        ];
    }

    public static function normalizeInput(string $verdict): string
    {
        $raw = strtolower(trim((string) $verdict));
        if ($raw === '') return self::UNKNOWN;

        $patterns = [
            'phishing' => self::MALICIOUS,
            'malware' => self::MALICIOUS,
            'malicious' => self::MALICIOUS,
            'danger' => self::MALICIOUS,
            'unsafe' => self::MALICIOUS,
            'high risk' => self::MALICIOUS,
            'suspicious' => self::SUSPICIOUS,
            'clean' => self::CLEAN,
            'safe' => self::CLEAN,
            'benign' => self::CLEAN,
            'not detected' => self::CLEAN,
            'no threat' => self::CLEAN,
            'error' => self::ERROR,
            'unknown' => self::UNKNOWN,
        ];

        foreach ($patterns as $needle => $canonical) {
            if (str_contains($raw, $needle)) {
                return $canonical;
            }
        }

        return self::UNKNOWN;
    }

    public static function aggregateLabel(string $verdict): string
    {
        $raw = strtolower(trim((string) $verdict));
        if ($raw === '') return 'Not enough data';

        if (str_contains($raw, 'phishing')) return 'Phishing';
        if (str_contains($raw, 'malware')) return 'Malware';
        if (str_contains($raw, 'malicious')) return 'Malicious';
        if (str_contains($raw, 'suspicious')) return 'Suspicious';
        if (str_contains($raw, 'danger') || str_contains($raw, 'unsafe') || str_contains($raw, 'high risk')) return 'Malicious';
        if (str_contains($raw, 'clean') || str_contains($raw, 'safe') || str_contains($raw, 'benign') || str_contains($raw, 'not detected') || str_contains($raw, 'no threat')) return 'Safe';
        if (str_contains($raw, 'error')) return 'Unable to scan';

        switch (self::normalizeInput($verdict)) {
            case self::MALICIOUS:  return 'Malicious';
            case self::SUSPICIOUS: return 'Suspicious';
            case self::CLEAN:      return 'Safe';
            case self::ERROR:      return 'Unable to scan';
            default:               return 'Not enough data';
        }
    }

    public static function aggregateLabelFromResults(array $results, string $fallbackVerdict = ''): string
    {
        if (is_array($results) && $results !== []) {
            foreach ($results as $result) {
                if (!($result instanceof self)) continue;
                $candidate = self::aggregateLabel((string) ($result->summary ?? '') . ' ' . (string) ($result->verdict ?? ''));
                if ($candidate !== 'Not enough data' && $candidate !== 'Unable to scan') {
                    return $candidate;
                }
            }
        }

        if ($fallbackVerdict !== '') {
            return self::aggregateLabel($fallbackVerdict);
        }

        return 'Not enough data';
    }
}
