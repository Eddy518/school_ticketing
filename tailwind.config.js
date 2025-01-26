/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./ticket/templates/**/*.html",
    "./ticket/static/src/**/*.js",
    "./node_modules/flowbite/**/*.js",
  ],
  theme: {
    extend: {},
  },
  plugins: [require("flowbite/plugin")],
};
