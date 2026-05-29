/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: '#0A0F1E',
        card: '#111827',
        blue: {
          electric: '#3B82F6',
        },
        threat: {
          drug: '#EF4444',
          cyber: '#F97316',
          traffic: '#8B5CF6',
          safe: '#10B981',
        }
      },
      fontFamily: {
        inter: ['Inter', 'sans-serif'],
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'count-up': 'countUp 1s ease-out forwards',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.6 },
        },
      },
      backdropBlur: {
        xs: '2px',
      }
    },
  },
  plugins: [],
}
