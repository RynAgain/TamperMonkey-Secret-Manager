/**
 * Password strength indicator with Art Deco styling.
 *
 * Scores passwords on length, character variety, and penalizes common patterns.
 * Purely visual guidance -- does not enforce any minimum strength.
 */

interface StrengthResult {
  score: number;
  label: string;
  color: string;
}

function calculateStrength(password: string): StrengthResult {
  if (!password) {
    return { score: 0, label: '', color: 'transparent' };
  }

  let score = 0;

  // Length scoring
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (password.length >= 20) score += 1;

  // Character variety
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^a-zA-Z0-9]/.test(password)) score += 1;

  // Penalties
  if (/^(.)\1+$/.test(password)) score = Math.max(0, score - 3); // All same char
  if (/^(012|123|234|345|456|567|678|789|abc|bcd|cde|def)/i.test(password)) {
    score = Math.max(0, score - 2); // Sequential patterns
  }
  // Common passwords penalty
  const common = ['password', '123456', '12345678', 'qwerty', 'letmein', 'admin', 'welcome'];
  if (common.includes(password.toLowerCase())) {
    score = 0;
  }

  // Map to labels
  const maxScore = 8;
  if (score <= 2) return { score, label: 'Weak', color: 'var(--color-danger)' };
  if (score <= 4) return { score, label: 'Fair', color: 'var(--color-warning)' };
  if (score <= 6) return { score: Math.min(score, maxScore), label: 'Good', color: 'var(--color-info)' };
  return { score: Math.min(score, maxScore), label: 'Strong', color: 'var(--color-success)' };
}

interface PasswordStrengthProps {
  password: string;
}

export default function PasswordStrength({ password }: PasswordStrengthProps) {
  const { score, label, color } = calculateStrength(password);

  if (!password) return null;

  const maxScore = 8;
  const percent = Math.min((score / maxScore) * 100, 100);

  return (
    <div className="mt-2">
      {/* Segmented strength bar with Art Deco geometric style */}
      <div
        className="relative h-2 rounded-sm overflow-hidden"
        style={{
          background: 'var(--color-bg-primary)',
          border: '1px solid var(--color-border-subtle)',
        }}
      >
        {/* Gold corner accents */}
        <div
          className="absolute top-0 left-0 w-1 h-full"
          style={{ background: 'var(--color-accent-gold)', opacity: 0.3 }}
        />
        <div
          className="absolute top-0 right-0 w-1 h-full"
          style={{ background: 'var(--color-accent-gold)', opacity: 0.3 }}
        />

        {/* Fill bar */}
        <div
          className="h-full transition-all duration-300 ease-out"
          style={{
            width: `${percent}%`,
            background: `linear-gradient(90deg, ${color}, ${color})`,
            opacity: 0.85,
          }}
        />

        {/* Segment dividers for Art Deco geometric feel */}
        <div className="absolute inset-0 flex">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-full"
              style={{
                width: '1px',
                marginLeft: `${(i / 4) * 100}%`,
                background: 'var(--color-bg-secondary)',
                position: 'absolute',
                left: 0,
              }}
            />
          ))}
        </div>
      </div>

      {/* Label */}
      <div className="flex justify-end mt-1">
        <span
          className="text-xs uppercase tracking-wider font-semibold transition-colors duration-300"
          style={{ color }}
        >
          {label}
        </span>
      </div>
    </div>
  );
}
