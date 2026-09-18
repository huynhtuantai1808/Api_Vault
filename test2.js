const fs = require('fs');
const guac = fs.readFileSync('static/js/guacamole.min.js', 'utf8');
const client_str = guac.substring(guac.indexOf('sendMessage('), guac.indexOf('sendMessage(')+100);
console.log(client_str);
