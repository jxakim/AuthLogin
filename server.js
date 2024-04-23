const express = require('express');
const app = express();

// set the view engine to ejs
app.set('view engine', 'ejs');


const port = 3000;

app.get('/', (req, res) => {
  res.send('Hello !');
});

app.listen(port, () => {
    console.log(`Connect to localhost:${port}`);
});
