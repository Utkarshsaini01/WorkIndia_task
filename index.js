require('dotenv').config();

const express = require('express');
const bodyParser = require("body-parser");
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const uuid = require('uuid');




const app = express();
app.use(express.json());

app.use(bodyParser.urlencoded({extended: true}));


const db = mysql.createConnection({
    host : process.env.host,
    user : process.env.user,
    password : process.env.dbpass,
    port : process.env.dbport,
    database : process.env.dbname,
});


db.connect((err)=>{
    if(err){
        console.log("Failed to connect");
        throw err;
    }

    console.log("connection successfull");
});


// // Api key for admin 
// const adminApiKey = process.env.adminApiKey;


// secret key for jsonwebtoken
const jwtSecretKey = process.env.jwtSecretKey;

// to verify api key for admin endpoints
function verifyApiKey(req, res, next){
    
    const apiKey = req.headers['adminkey'];
    
    if(apiKey == process.env.adminApiKey){
        next();
    }
    else {
        return res.status(401).json({status : 'Unauthorized'});
    }
}


// to verify JWT token for protected routes
function verifyJWTToken(req, res, next){
    const token = req.headers.authorization;
    // console.log(token);

    if(token){
        return res.status(401).json({status : 'Unauthorized'});
    }

    jwt.verify(token.split(' ')[1], jwtSecretKey, (err, decode) => {
        if(err){
            return res.status(401).json({status : 'unauthorized'});
        }

        req.userId = decode.userId;
        next(); 
    });
}




// subtask - 1 Register API
app.post('/api/signup', (req, res) => {
    const { username, password, email } = req.body;

    // Hashing the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ status: err });
        }

        const userId = uuid.v4(); // Generate a unique user ID

        // Insert user data into the database
        const sql = 'INSERT INTO users (user_id, username, password, email) VALUES (?, ?, ?, ?)';
        db.query(sql, [userId, username, hashedPassword, email], (err) => {
            if (err) {
                return res.status(500).json({ status: err });
            }
            return res.status(200).json({ status: 'Account successfully created', status_code: 200, user_id : userId });
        });
    });
});



// subtask - 2 Login API
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    const sql = 'SELECT user_id, password FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ status: 'Incorrect username/password provided. Please retry', status_code: 401 });
        }

        const hashedPassword = results[0].password;
        const userId = results[0].user_id;

        // Compare the provided password with the stored hash
        bcrypt.compare(password, hashedPassword, (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'Internal Server Error' });
            }

            if (result) {
                // Generate and return a JWT token on successful login
                const jwtToken = jwt.sign({ userId }, jwtSecretKey, { expiresIn: '1h' });
                return res.status(200).json({
                    status: 'Login successful',
                    status_code: 200,
                    user_id: userId,
                    access_token: jwtToken,
                });
            } else {
                return res.status(401).json({ status: 'Incorrect username/password provided. Please retry', status_code: 401 });
            }
        });
    });
});


// Subtask -3 Add a New Book - Admin can only add
app.post('/api/books/create', verifyApiKey, (req, res) => {
    const { title, author, isbn } = req.body;

    const bookId = uuid.v4();

    const sql = 'INSERT INTO books (book_id, title, author, isbn) VALUES (?, ?, ?, ?)';
    db.query(sql, [bookId, title, author, isbn], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ status: 'Internal Server Error' });
        }
        
        return res.status(200).json({ message: 'Book added successfully', book_id: bookId });
    });
});



// subtask - 4 Search for a Book using title
app.get('/api/books/', (req, res) => {
    const searchQuery = req.query.title;
    console.log(searchQuery);

    const sql = 'SELECT * FROM books WHERE title LIKE ?';
    db.query(sql, [searchQuery], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'Internal Server Error' });
        }
        return res.status(200).json({ results });
    });
});



// subtask - 5 check Book Availability
app.get('/api/books/:book_id/availability', (req, res) => {
    const bookId = req.params.book_id;

    // Check if the book is available for booking
    const sql = 'SELECT * FROM bookings WHERE book_id = ? AND return_time > NOW() ORDER BY return_time ASC LIMIT 1';
    db.query(sql, [bookId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'Internal Server Error' });
        }

        if (results.length === 0) {
            // The book is available
            res.status(200).json({
                book_id: bookId,
                available: true,
            });
        } else {
            // The book is not available, return the next available time
            res.status(200).json({
                book_id: bookId,
                available: false,
                next_available_at: results[0].return_time,
            });
        }
    });
});


// Task - 6 Borrow a Book - User Only
app.post('/api/books/borrow', verifyJWTToken, (req, res) => {
    const { book_id, user_id, issue_time, return_time } = req.body;

    
    const availabilitySql = 'SELECT * FROM bookings WHERE book_id = ? AND return_time > NOW() ORDER BY return_time ASC LIMIT 1';
    db.query(availabilitySql, [book_id], (err, results) => {
        if (err) {
            
            return res.status(500).json({ status: 'Internal Server Error' });
        }
        // console.log(book_id);
        if (results.length === 0) {
            // The book is available for booking
            const bookingId = uuid.v4();
            

            // Insert booking data into the database
            const bookingSql = "INSERT INTO bookings (booking_id, book_id, user_id, issue_time, return_time) VALUES (?, ?, ?, ?, ?)";
            db.query(bookingSql, [bookingId, book_id, user_id, issue_time, return_time], (err, result) => {
                if (err) {
                    // console.log(err);
                    return res.status(500).json({ status: err });
                }
                return res.status(200).json({ status: 'Book booked successfully', status_code: 200, booking_id: bookingId });
            });
        } else {
            // The book is not available
            return res.status(400).json({ status: 'Book is not available at this moment', status_code: 400 });
        }
    });
});



let port = process.env.PORT;
if(port == null || port ==""){
  port = 3000;
}

app.listen(port, function(){
  console.log("Server is Started Successfully and running at port 3000 locally");
});
