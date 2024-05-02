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
    const sql = "SELECT * FROM userdata WHERE username = ?";
    const query = await initiateQuery(sql, [username]);

    if (query.length > 0 && query[0].twoFAkey) {
        return true;
    } else {
        return false;
    }
}


async function LoginUser(res, username) {
    const cookie_time_minutes = 5;
    res.cookie('loggedin', true, { maxAge: cookie_time_minutes * 60 * 1000, httpOnly: true });
    res.cookie('user', username, { maxAge: cookie_time_minutes * 60 * 1000, httpOnly: true });

    res.render('home', { username: username, hasTwoFASetup: await hasTwoFASetup(username) });
}

async function LogoutUser(req, res) {
    const username = req.cookies.user;

    res.cookie('loggedin', true, { maxAge: 0, httpOnly: true });
    res.cookie('user', username, { maxAge: 0, httpOnly: true });

    res.render('login', { message: null });
}

async function verify_totp(code, username, res) {
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
            LoginUser(res, username);
        } else {
            // Invalid code
            res.render('login', { message: 'Invalid TOTP code' });
        }
    }
}

// ---------------------------------------------- Content ---------------------------------------------- //

app.get('/login', async (req, res) => {
    if (req.cookies.loggedin) {
        res.render('home', { message: null });
    } else {
        res.render('login', { message: null });
    } 
})

app.get('/logout', async (req, res) => {
    if(req.cookies.loggedin) {
        LogoutUser(req, res);
    } else {
        res.render('login', { message: 'You have been logged out.' });
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
                    const twofa = await hasTwoFASetup(username);
                    twofa ? res.render('2fa_verify', {username: username}) : LoginUser(res, username);

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
    
            if (password !== passwordrepeat) {
                res.render("change_pass", { message: "Passwords do not match." });
            } else {
                let hashedPassword = await bcrypt.hash(password, 10);

                const query = "UPDATE userdata SET pswHash = ? WHERE username = ?";
                const sql = await initiateQuery(query, [hashedPassword, username]);

                const query2 = "UPDATE userdata SET tempPsw = null WHERE username = ?";
                await initiateQuery(query2, [username]);
                
                if(sql) {
                    LoginUser(res, username)
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

app.post('/verify-2fa', async (req, res) => {
    try {
        const {username, code} = req.body;

        verify_totp(code, username, res);

    } catch (err) {
        console.error('Error verifying 2FA:', err);
        res.status(500).send('Internal Server Error');
    }
});


app.post('/verify-totp', async (req, res) => {
    try {
        const {code} = req.body;
        const username = req.cookies.user;
        verify_totp(code, username, res);

    } catch (err) {
        console.error('Error verifying TOTP code:', err);
        res.status(500).send('Internal Server Error');
    }
});


app.listen(port, () => {
    console.clear();
    console.log(`Connect to localhost:${port}`);
});
