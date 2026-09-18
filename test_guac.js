const fs = require('fs');
const guac = fs.readFileSync('static/js/guacamole.min.js', 'utf8');
console.log(guac.includes("Guacamole.Client"));
