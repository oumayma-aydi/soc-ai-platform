/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        soc: {
          950: "#060D1A",
          900: "#0A1628",
          800: "#0F1E35",
          700: "#162947",
        },
        star: {
          400: "#A3D44E",
          500: "#78BE20",
          600: "#5E9918",
          700: "#3D6610",
        },
        threat: {
          critical: "#EF4444",
          high:     "#F97316",
          medium:   "#EAB308",
          low:      "#3B82F6",
        }
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      boxShadow: {
        "star":   "0 0 20px rgba(120, 190, 32, 0.15)",
        "threat": "0 0 20px rgba(239, 68, 68, 0.15)",
      }
    },
  },
  plugins: [],
};
