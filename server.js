const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const app = express();

// set the view engine to ejs
app.set('view engine', 'ejs');

app.use(express.static(__dirname + '/public'));
app.use(express.urlencoded({ extended: true }));

const port = 3000;

// ---------------------------------------------- Database ---------------------------------------------- //

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'authlogin',
});
  
db.connect((err) => { if (err) throw err });
  
// ---------------------------------------------- Functions ---------------------------------------------- //
  
// SQL Query håndtering
function initiateQuery(sql, values) {
    return new Promise((resolve, reject) => {
        db.query(sql, values, (err, result) => {
        if (err) reject(err);
        resolve(result);
        });
    });
}

// ---------------------------------------------- Content ---------------------------------------------- //

app.route('/')
    .get(async (req, res) => {
        res.render('login');
    })
    
    .post(async (req, res) => {
        try {
            const { username, password } = req.body;
            const sql = 'SELECT * FROM userdata WHERE TRIM(username) = ?';
            const query = await initiateQuery(sql, [username]);
            
            if(!query) {
                res.render('/', { message: 'User does not exist.' });
            } else {
                if(!query[0].pswHash) {
                    // This means the user has not set a password yet
                    // User will be sent to a password change route IF password matches with the temp psw
                    if(password === query[0].tempPsw) {
                        res.render('change_pass');
                    }  else if(!query[0].tempPsw && bcrypt.compare(password, query[0].tempPsw)) {
                        console.log(query[0].tempPsw, bcrypt.compare(password, query[0].tempPsw));
                    }
                } else if(!query[0].tempPsw) {
                    
                }
            }

        } catch (err) {
            console.error("Error: " + err);
        }
    });


app.route('/create_password')
    .post(async (req, res) => {
        try {
            const { password, passwordrepeat } = req.body;
    
            console.log(password, passwordrepeat);
    
            if (password !== passwordrepeat) {
                res.render("change_pass", { message: "Passwords do not match." });
            } else {
                let hashedPassword = await bcrypt.hash(password, 10);
                const query = "UPDATE userdata SET pswHash = ? WHERE username = ?";
                const sql = await initiateQuery(query, [hashedPassword, "admin"]);
                
                if(sql) {
                    res.render("home", { message: null });
                }
            }
    
        } catch (err) {
            console.log("Error: " + err);
        }
    });


app.listen(port, () => {
    console.clear();
    console.log(`Connect to localhost:${port}`);
});
