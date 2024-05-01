const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const app = express();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const fs = require('fs');
const path = require('path');
const { QuickReplyAction } = require('twilio/lib/rest/content/v1/content');

// set the view engine to ejs
app.set('view engine', 'ejs');

app.use(express.static(__dirname + '/public'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

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

// Function to generate a secret key and QR code URL
async function generateSecret() {
    const secret = speakeasy.generateSecret({ length: 20 });
    const otpauthUrl = speakeasy.otpauthURL({
        secret: secret.base32,
        label: 'AuthLogin',
        issuer: 'AuthLogin',
        algorithm: 'sha1', // Use the same algorithm supported by Microsoft Authenticator
    });
    const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);
    return { secret, qrCodeUrl };
}

// Function to generate QR code image
async function generateQRCode(text, filePath) {
    try {
        await qrcode.toFile(filePath, text);
        console.log('QR code generated successfully:', filePath);
    } catch (err) {
        console.error('Error generating QR code:', err);
    }
}

async function hasTwoFASetup(username) {
    const username = req.cookies.user

    // Check if user has  already set up 2FA
    const sql = "select twoFAkey from userdata where username = ?";
    const query = initiateQuery(sql, [username]);

    if(query[0]) {
        if(query[0].twoFAkey !== null) {
            return true;
        }
    } else {
        return false;
    }
}

async function LoginUser(res, username) {
    const cookie_time_minutes = 5;
    res.cookie('loggedin', true, { maxAge: cookie_time_minutes * 60 * 1000, httpOnly: true });
    res.cookie('user', username, { maxAge: cookie_time_minutes * 60 * 1000, httpOnly: true });

    // Password matches
    res.render('home', { message: null });
}

// ---------------------------------------------- Content ---------------------------------------------- //

app.get('/login', async (req, res) => {
    if (req.cookies.loggedin) {
        res.render('home', { message: null });
    } else {
        res.render('login', { message: null });
    } 
})

app.route('/')
    .get(async (req, res) => {
        if (req.cookies.loggedin) {
            res.render('home', { message: null });
        } else {
            res.render('login', { message: null });
        }
    })
    
    .post(async (req, res) => {
        try {
            const { username, password } = req.body;
            const sql = 'SELECT * FROM userdata WHERE TRIM(username) = ?';
            const query = await initiateQuery(sql, [username]);
            
            if(!query[0]) {
                res.render('login', { message_username: 'User does not exist.' });

            } else if(!query[0].pswHash) {
                // This means the user has not set a password yet
                // User will be sent to a password change route IF password matches with the temp psw

                if(password === query[0].tempPsw) {
                    res.render('change_pass', { username });

                } else if(query[0].tempPsw) {
                    res.render('login', { message_password: 'Wrong password.' });

                } else {
                    res.render('login', { message: 'Something wrong happened.' });
                }
            } else if(!query[0].tempPsw) {
                const passwordMatches = await bcrypt.compare(password, query[0].pswHash);
                if(passwordMatches) {

                    if(hasTwoFASetup(username)) {
                        res.render('2fa_verify');
                    } else {
                        LoginUser(res, username);
                    }
                } else {
                    // Password does not match
                    res.render('login', { message_password: 'Wrong password.' });
                }
            }

        } catch (err) {
            console.error("Error: " + err);
        }
    });


app.route('/create_password')
    .post(async (req, res) => {
        try {
            const { username, password, passwordrepeat } = req.body;
    
            console.log(username);
    
            if (password !== passwordrepeat) {
                res.render("change_pass", { message: "Passwords do not match." });
            } else {
                let hashedPassword = await bcrypt.hash(password, 10);
                const query = "UPDATE userdata SET pswHash = ? WHERE username = ?";
                const sql = await initiateQuery(query, [hashedPassword, "admin"]);

                const query2 = "UPDATE userdata SET tempPsw = null WHERE username = ?";
                const sql2 = await initiateQuery(query2, [username]);
                
                if(sql) {
                    const cookie_time_minutes = 5;
                    res.cookie('loggedin', true, { maxAge: cookie_time_minutes * 60 * 1000, httpOnly: true });
                    res.cookie('user', username, { maxAge: cookie_time_minutes * 60 * 1000, httpOnly: true });

                    res.render("home", { message: null });
                }
            }
    
        } catch (err) {
            console.log("Error: " + err);
        }
    });


app.get('/setup-2fa', async (req, res) => {
    try {
        const { secret, qrCodeUrl } = await generateSecret(); // Wait for the QR code generation
        const username = req.cookies.user;

        const query = 'UPDATE userdata SET twoFAkey = ? WHERE username = ?';
        await initiateQuery(query, [secret.base32, username]);

        const filePath = path.join(__dirname, 'public', 'img', 'qrcode.png'); // Path where the QR code image will be saved

        await generateQRCode(secret.otpauth_url, filePath); // Wait for the QR code image generation

        // Render the EJS template and pass the QR code URL and other necessary data
        res.render('2fa_setup', { qrCodeUrl, secret, username });

    } catch (err) {
        console.error('Error generating 2FA setup:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/verify-2fa', async (req, res) => {
    try {
        const username = req.cookies.user

        if(hasTwoFASetup(username)) {
            res.render('2fa_verify');
        } else {
            console.log("2fa is not set up for this user.");
        }

    } catch (err) {
        console.error('Error verifying 2fa:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/verify-totp', async (req, res) => {
    try {
        const { code } = req.body;
        const username = req.cookies.user;

        const sql = 'select twoFAkey from userdata where username = ?';
        const query = await initiateQuery(sql, [username]);

        if(query[0]) {

            // Verify the TOTP code entered by the user
            const verified = speakeasy.totp.verify({
                secret: query[0].twoFAkey,
                encoding: 'base32',
                token: code,
                window: 2,
            });
            if (verified) {
                // Authentication successful
                console.log("User verified");
                res.render('home', { message: 'welcome' }); // Redirect to dashboard or home page
            } else {
                // Invalid code
                res.render('login', { message: 'Invalid TOTP code' });
            }
        }

    } catch (err) {
        console.error('Error verifying TOTP code:', err);
        res.status(500).send('Internal Server Error');
    }
});


app.listen(port, () => {
    console.clear();
    console.log(`Connect to localhost:${port}`);
});
