/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          void: '#0B0F17',
          surface: '#111827',
          card: '#1F2937',
          border: 'rgba(255, 255, 255, 0.08)',
          accent: '#3B82F6',
          critical: '#EF4444',
          warning: '#F97316',
          anomaly: '#EAB308',
          success: '#10B981',
          synthetic: '#8B5CF6'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
