import { Sun, Moon, Monitor } from 'lucide-react';
import { useTheme } from '../hooks/useTheme.ts';

function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  const options = [
    { value: 'light' as const, icon: Sun, label: 'Light' },
    { value: 'system' as const, icon: Monitor, label: 'Auto' },
    { value: 'dark' as const, icon: Moon, label: 'Dark' },
  ];

  return (
    <div className="flex rounded-lg overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
      {options.map(({ value, icon: Icon, label }) => (
        <button
          key={value}
          type="button"
          onClick={() => setTheme(value)}
          className="flex items-center gap-1 px-3 py-1.5 text-[12px] font-medium transition-colors"
          style={
            theme === value
              ? { backgroundColor: '#007AFF', color: '#FFFFFF' }
              : { color: 'var(--text-secondary)' }
          }
        >
          <Icon className="h-3.5 w-3.5" />
          {label}
        </button>
      ))}
    </div>
  );
}

export default ThemeToggle;
