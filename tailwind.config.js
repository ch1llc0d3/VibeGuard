/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx}',
    './src/components/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        danger: {
          100: '#FFD1CF',
          500: '#FF3B30',
          800: '#CC2F26',
        },
        warning: {
          100: '#FFF0B3',
          500: '#FFCC00',
          800: '#CC9900',
        },
        secure: {
          100: '#D1F0DB',
          500: '#34C759',
          800: '#248A3D',
        },
      },
    },
  },
  plugins: [],
}