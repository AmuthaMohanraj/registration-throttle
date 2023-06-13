// import express, cors, mysql , dotenv, bcrypt
const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// Create an in-memory cache to store blocked users
const blockedUsers = new Map();


//create express app
const app = express();
app.use(express.json());
app.use(cors());


//connect mysql
const connection = mysql.createConnection({
    host: process.env.HOST_NAME,
    user: process.env.USER_NAME,
    password: process.env.PASSWORD,
    database: process.env.DB_NAME
});

connection.connect((err) => {
    if (err) throw err;
    console.log('Database connected');
});

//create mail transporter verify transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

transporter.verify((err, success) => {
    if (err) {
        console.log(err);
    }
    if (success) {
        console.log('Mail Server is ready to take messages');
    }
});


//create function to sent mail to user using nodemailer transporter 

// let htmlLink= `<html><body><br><br><p>please verify your mail <a href=">${process.env.DOMAIN}/verify/?token=${token}" > click </a> </p> </body> </html>`;
const sendMail = (email, token, res,) => {
    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Verify your account',
        html: `<h1>Click on the link to verify your account</h1><br/> <p>${process.env.DOMAIN}/verify/?token=${token}</p>`,
        // html: htmlLink
    };
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            res.send({ err: 'something went wrong' });
        }
        if (info) {
            res.send({ success: 'check your email to verify your account' });
        }
    }
    );
};





// step1: create route signup
// step2: get username,email,password as data from body and  add validation for username, email, password
// step3: use bcrypt to hash password
// step4: verify email does not exist in user table if exist then check isVerified column is 0 or 1 if 0 then send mail to user to verify account else send response as error
// step5: if success  insert into database and table name users and use ? in sql query to prevent sql injection else send response as own error  message
// step6: if success create jwt token using hash password 
// step7: sent mail with jwt token as parameter in href link to user email to verify account
// step8: if error send response as error and success as success

app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;
    if ((username && username !== null && username !== undefined && username !== '') && (email && email !== null && email !== undefined && email !== '') && (password && password !== null && password !== undefined && password !== '')) {
        const hash = bcrypt.hashSync(password, 10);
        const token = jwt.sign({ mail: email, username: username }, process.env.SECRET_KEY);
        connection.query('SELECT email,isVerified FROM users_table WHERE email=?', [email], (err, result) => {
            if (err) {
                res.send({ err: '1. something went wrong' });
            }
            if (result.length > 0) {
                if (result[0].isVerified === 0) {
                    sendMail(email, token, res);
                } else {
                    res.send({ err: '2.something went wrong' });
                }
            }
            if (result.length === 0) {
                connection.query('INSERT INTO users_table (username,email,password) VALUES (?,?,?)', [username, email, hash], (err, result) => {
                    if (err) {
                        res.send({ err: '3.something went wrong' });
                    }
                    if (result) {
                        sendMail(email, token, res);
                    }
                });
            }
        });
    } else {
        res.send({ err: 'something went wrong' });
    }
});

// step1: create route verify
// step2: get token from body and add validation for token
// strp3: if token is not null then verify token using jwt verify method  else send response as error
// step4: if success update isVerified column in users table
// step5: if error send response as error and success as success.


app.put('/verify', (req, res) => {
    const { token } = req.body;
    if (token && token !== null && token !== undefined && token !== '') {
        jwt.verify(token, process.env.SECRET_KEY, (err, result) => {
            if (err) {
                res.send({ err: 'something went wrong' });
            }
            if (result) {
                connection.query('UPDATE users_table SET isVerified=? WHERE email=?', [1, result.mail], (err, result) => {
                    if (err) {
                        res.send({ err: 'something went wrong' });
                    }
                    if (result) {
                        res.send({ success: 'your account is verified' });
                    }
                });
            }
        });
    } else {
        res.send({ err: 'something went wrong' });
    }
});

// step1: create route login
// step2: get email,password from body and add validation for email,password
// step3: if email and password is not null then verify email exist in users table
// step4: if email exist then verify isVerified column is 0 or 1 if 0 then send mail to user to verify account else send response as error
// step5: if email does not exist then send response as error
// step6: if email exist and isVerified column is 1 then verify password using bcrypt compare method
// step7: if password is correct then create jwt token using hash password and send response as success
// step8: if password is incorrect then send response as error


// login route with incrementAttempt function
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (email && password) {
        connection.query('SELECT email,password,isVerified from users_table where email=?', [email], (err, result) => {
            if (err) {
                console.log(err);
                return res.status(500).send({ err: 'Something went wrong' });
            }

            if (result.length > 0) {
                connection.query('SELECT blocked from users_table WHERE email = ?', [email], (err, selectResult) => {
                    if (err) {
                        console.log(err);
                        return;
                    }
                    if(selectResult.length > 0){
                         console.log(selectResult,'selectResult');
                    if (selectResult[0].blocked === 0) {                   //check if user is verified
                        if (result[0].isVerified === 0) {
                            const token = jwt.sign({ mail: email, username: result[0].username }, process.env.SECRET_KEY);
                            sendMail(email, token, res);
                        } else {
                            const isMatch = bcrypt.compareSync(password, result[0].password);
                            if (isMatch) {
                                const token = jwt.sign({ mail: email, username: result[0].username }, process.env.SECRET_KEY);
                                res.send({ success: token });
                            } else {
                                res.send({ err: 'Wrong password' });
                                incrementAttempt(email);              //call incrementAttempt function
                            }
                        }
                    }
                     else {
                        res.send({ err: 'You are blocked. Please try again later.' });
                        return
                    }
                }    else {
                    res.send({ err: 'Something went wrong' });
                }

                });
            }

            else {
                res.send({ err: 'Create Account' });
            }
        });
    } else {
        res.send({ err: 'Something went wrong' });
    }
});


//   incrementAttempt function 
const incrementAttempt = (email) => {
    if(!email){
        return
    }
    connection.query('select attempts from users_table WHERE email=?',[email], (err, result) => {
          if(result.length>0){
            connection.query('UPDATE users_table SET attempts=? WHERE email=?', [result[0].attempts + 1, email], (err, updateResult) => {
                if (err) {
                    console.log(err);
                    return;
                }

                if (updateResult && updateResult.affectedRows > 0) {
                    checkAttempts(email)                              //to call checkAttempts function
                };
            })
        } 
     });
    }   

// checkAttempts function
let i = 0;
const checkAttempts = (email) => {
    connection.query('SELECT email,attempts FROM users_table WHERE email=?', [email], (err, result) => {
        if (err) {
            console.log(err);
            return;
        }
        if (result.length > 0) {
            if (result[0].attempts >= 3) {
                console.log('user blocked');
                blockUser(result[0].email);            //To call Block the user function
                i = 0;
                // res.send({ err: 'user blocked' });
                return true;
            } else {
                console.log(`attempts incremented ${++i}`);
                // res.json({ err: 'second attempt' });
                return false;
            }
        }
    });
}

// step1:create route logout
app.put('/logout', (req, res) => {
    const { email } = req.body;
    if (email) {
        connection.query('UPDATE users_table SET attempts=?, isActive=? WHERE email=? ', [0, 0, email], (err, result) => {
            if (err) {
                console.log(err);
                return;
            }
            if (result) {
                res.send({ success: 'logout successfully' });
            }

        });
    } else {
        res.send({ err: 'something went wrong' });
    }
});



// block user function
// Block user for 3 hours
// Block user for 3 hours
let blockUser = (email) => {
    if (email) {
      const blockTime = 1 * 60 * 1000; // 1 minute in milliseconds
    // const blockTime = 10 * 60 * 1000; // 10 minutes in milliseconds
    // onst blockTime= 15 * 60 * 1000; // 15 minutes in milliseconds
    //   const blockTime = 3 * 60 * 60 * 1000; // 3 hours in milliseconds

    //   const unblockTime = Date.now() + blockTime;


    const unblockTime = Math.floor((Date.now() + blockTime) / 1000); // Convert to seconds
    console.log(unblockTime, 'unblockTime')
      connection.query(`UPDATE users_table SET blocked=?, blockedTime=FROM_UNIXTIME(?)  WHERE email=?`, [1, unblockTime, email], (err, result) => {
        if (err) {
          console.log(err);
          return;
        }
        if (result) {
          console.log({ success: 'blocked' });
  
          setTimeout(() => {
            unblockUser(email);
          }, blockTime);
        }
      });
    } else {
      console.log({ err: 'something went wrong' });
    }
  };
  

  // Unblock user
const unblockUser = (email) => {
    connection.query(`UPDATE users_table SET attempts=?,blocked=?, blockedTime=NULL WHERE email=?`, [0,0,email], (err, result) => {
      if (err) {
        console.log(err);
        return;
      }
      if (result) {
        console.log({ success: 'unblocked' });
      }
    });
  };
  

app.listen(3000, () => {
    console.log('server started');
}
);
