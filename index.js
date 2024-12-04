/**
 * Dependencies.
 */
const express = require("express");
const path = require('path');
const session = require('express-session');
const User = require("./models/BBY_31_users");
const Chat = require("./models/BBY_31_messages");
const Cart = require("./models/BBY_31_shoppingCarts");
const mongoose = require("mongoose");
const multer = require("multer");
const bcrypt = require('bcrypt');
const app = express();
const http = require('http');
const server = http.createServer(app);
const {
    Server
} = require("socket.io");
const io = new Server(server);
const nodemailer = require('nodemailer');

/**
 * MangoDB connection.
 */
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();  // Load environment variables from .env file in non-production environments
}

mongoose.set('strictQuery', false);  // Disable strict query mode for Mongoose (if needed)

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/db', { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
})
.then(() => {
    console.log("Connected to MongoDB");
})
.catch((err) => {
    console.log("MongoDB connection error:", err);
});


/**
 * Middlewares to set up view engine.
 */
app.set('view engine', 'text/html');
app.use(express.urlencoded({
    extended: true
}));
app.use(express.static(__dirname + '/public'));
app.use(session({
    secret: "password",
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 10800000
    }
}));

//Custom middleware functions
/**
 * This function checks to see if a user is logged in.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns next if user is logged in or redirects to login page.
 */
function isLoggedIn(req, res, next) {
    if (req.session.isLoggedIn) {
        return next();
    } else {
        return res.redirect('/login');
    }
}

/**
 * 
 * This function checks to see if a user is logged out.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns next if user is logged out or redirects to userprofile page.
 */
function isLoggedOut(req, res, next) {
    if (!req.session.isLoggedIn) {
        return next();
    } else {
        return res.redirect('/userprofile');
    }
}

/**
 * 
 * This function checks to see if a user is an administrator.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns returns to login page if user is not logged in, next if user is administrator, 
 * or returns to home page if user is not admin AND is logged in.
 */
function isAdmin(req, res, next) {
    let userId = req.session.user._id;
    User.findById({
        _id: userId
    }, function (err, user) {
        if (err) console.log(err)
        else if (!user) {
            return res.redirect('/login')
        }
        if (user.userType == 'admin') {
            return next();
        } else {
            return res.redirect('/userprofile');
        }
    })
}

/**
 * 
 * This function stops the browsers from storing protected pages on cache
 * -User cannot backspace to previous page if page is protected(Eg. not logged in).
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns calls next middleware function.
 */
function setHeaders(req, res, next) {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate"); // HTTP 1.1.
    res.setHeader("Pragma", "no-cache"); // HTTP 1.0.
    res.setHeader("Expires", "0"); // Proxies.
    return next();
}

/**
 * 
 * This function checks to see if a user has recently purchased a session within the last three minutes
 * This function helps with displaying a thank-you page upon purchase.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns next if a user has recently placed an order or redirects to home page.
 */
async function hasRecentlyPurchased(req, res, next) {
    //If a purchase was made in the last 3 mins, render thank-you page
    var currentTime = new Date();
    var nowMinus3Mins = new Date(currentTime.getTime() - 3 * 60000);

    var recentOrderExists = await Cart.exists({
        userId: req.session.user._id,
        status: "completed",
        purchased: {
            $gt: nowMinus3Mins
        }
    })

    if (recentOrderExists) {
        return next();
    } else {
        return res.redirect('/');
    }
}

/**
 * 
 * This function checks to see if a user has an active session with a therapist.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns next if a user has an active session or redirects to home page.
 */
async function hasActiveSession(req, res, next) {
    var currentTime = new Date();

    var patientActiveSession = await Cart.exists({
        $or: [{
            therapist: req.session.user._id
        }, {
            userId: req.session.user._id
        }],
        status: "completed",
        expiringTime: {
            $gt: currentTime
        }
    })
    if (patientActiveSession) {
        return next();
    } else {
        return res.redirect('/');
    }
}

/**
 * 
 * Since therapist and patients have a one-to-one relationship, this function checks to see if a therapist is available.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns if a therapist has an active session with another user it will return an error message, else it will
 * return next.
 */
async function isTherapistAvailable(req, res, next) {
    var currentTime = new Date();

    let orderExists = await Cart.exists({
        therapist: req.body.therapistID,
        status: "completed",
        expiringTime: {
            $gt: currentTime
        }
    })
    if (orderExists) {
        return res.json({
            errorMsg: "Therapist is currently busy. Please delete him from your cart or wait until they become available again."
        });
    } else {
        return next();
    }
}

/**
 * 
 * This function checks to see if the logged in user is a patient
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns next if the user is a patient, else redirects to home page.
 */
function isPatient(req, res, next) {
    if (req.session.user.userType == 'patient') {
        return next();
    }
    return res.redirect('/');
}

//Routes

/**
 * This get route renders the home (index.html) page.
 */
app.get('/', function (req, res) {
    res.sendFile(path.resolve('html/index.html'));
});

/**
 * This get route renders the therapist.html page.
 */
app.get('/therapists', function (req, res) {
    res.sendFile(path.resolve('html/therapists.html'));
});

/**
 * This get route renders the chat-session.html page.
 */
app.get('/chat-session', isLoggedIn, hasActiveSession, setHeaders, function (req, res) {
    res.sendFile(path.resolve('html/chat-session.html'));
});

/**
 * This get route renders the my-patient.html page.
 */
app.get('/my-patients', isLoggedIn, setHeaders, function (req, res) {
    res.sendFile(path.resolve('html/my-patients.html'));
});

/**
 * This get route renders the checkout.html page.
 */
app.get('/checkout', isLoggedIn, isPatient, setHeaders, function (req, res) {
    res.sendFile(path.resolve('html/checkout.html'));
});

/**
 * This get route renders the privacypolicy.html page.
 */
app.get('/privacypolicy', function (req, res) {
    res.sendFile(path.resolve('html/privacypolicy.html'));
});

/**
 * This get route renders the termsandconditions.html page.
 */
app.get('/termsandconditions', function (req, res) {
    res.sendFile(path.resolve('html/termsandconditions.html'));
});

/**
 * This get route renders order-history.html page.
 */
app.get('/order-history', isLoggedIn, isPatient, setHeaders, function (req, res) {
    res.sendFile(path.resolve('html/order-history.html'));
});

/**
 * This get route renders thank-you.html page.
 */
app.get('/thank-you', isLoggedIn, hasRecentlyPurchased, setHeaders, function (req, res) {
    res.sendFile(path.resolve('html/thank-you.html'));
});

/**
 * This get route renders the login.html page.
 */
app.get("/login", isLoggedOut, setHeaders, (req, res) => {
    res.sendFile(path.resolve('html/login.html'));
});

/**
 * This get route renders the admin-dashboard.html page.
 */
app.get('/admin-dashboard', isLoggedIn, isAdmin, setHeaders, (req, res) => {
    res.sendFile(path.resolve('html/admin-dashboard.html'))
});

/**
 * This get route renders userprofile.html page.
 */
app.get('/userprofile', isLoggedIn, setHeaders, (req, res) => {
    res.sendFile(path.resolve('html/userprofile.html'))
})

/**
 * This get route renders edit-account.html page.
 */
app.get('/edit-account', isLoggedIn, setHeaders, (req, res) => {
    res.sendFile(path.resolve('html/edit-account.html'))
})

/**
 * This get route renders sign-up.html page.
 */
app.get("/sign-up", isLoggedOut, setHeaders, (req, res) => {
    res.sendFile(path.resolve('html/sign-up.html'))
})

/**
 * This variable initializes a diskStorage for multer.
 * Multer is a dependency that stores user profile images.
 */
var profileStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + file.originalname);
    }
})
var profileUpload = multer({
    storage: profileStorage
})

/**
 * This post route allows users to upload their profile images onto mongodb.
 */
app.post('/uploadProfile', profileUpload.single('profileFile'), (req, res) => {
    if (req.file) {
        var fileName = req.file.filename;
        var id = req.session.user._id;
        User.updateOne({
            "_id": id
        }, {
            profileImg: "../uploads/" + fileName
        }).then((obj) => {})
    } else {
        return;
    }
});

/**
 * This get route will get the uploaded images from mongodb and render them on the html.
 */
app.get('/getProfilePicture', (req, res) => {
    var id = req.session.user._id;
    User.findById({
        _id: id
    }, function (err, user) {
        if (user) {
            res.send(user)
        }
    })
})

/**
 * This get route checks to see if a user is logged in.
 */
app.get('/isLoggedIn', (req, res) => {
    res.send(req.session.user);
})

/**
 * This get route finds the user by their id from the database and returns
 * the user and their information as an object.
 */
app.get('/getUserInfo', isLoggedIn, setHeaders, (req, res) => {
    let userId = req.session.user._id;
    User.findById({
        _id: userId,
    }, function (err, user) {
        if (err) console.log(err)
        if (user) {
            res.json(user);
        }
    })
})

/**
 * This post route finds a patient by their id from the database and returns
 * the patient and their information as an object.
 */
app.post('/getPatientInfo', isLoggedIn, setHeaders, (req, res) => {
    let userId = req.body._id
    User.findById({
        _id: userId,
    }, function (err, user) {
        if (err) console.log(err)
        if (user) {
            res.json(user);
        }
    })
})

/**
 * 
 * This helper function for /getTherapists checks to see if a therapist has an active session with another user.
 * 
 * @param {*} therapistInfo as therapist id
 * @returns true if therapist has an active session OR false if they don't.
 */
async function therapistHasActiveSession(therapistInfo) {
    var currentTime = new Date();
    let orderExists = await Cart.exists({
        therapist: therapistInfo._id,
        status: "completed",
        expiringTime: {
            $gt: currentTime
        }
    })
    if (orderExists) {
        return true;
    } else {
        return false
    }
}

/**
 * This get route looks for all users with the type "therapist" and returns
 * the therapist that do not have an active session as an array.
 */
app.get('/getTherapists', (req, res) => {
    User.find({
        userType: "therapist"
    }, async function (err, user) {
        if (err) console.log(err)
        if (user) {
            var existingSession;
            for (let i = 0; i < user.length; i++) {
                existingSession = await therapistHasActiveSession(user[i])
                if (existingSession) {
                    user.splice(i, 1);
                }
            }
            return res.json(user)
        }
    }).sort({
        numSessions: 'desc'
    })
})

/**
 * This post route verifies the users email and password when logging in
 * If the user has an invalid email, it will return "NoEmailExists", return
 * user to login if an error occurs or calls auth (a helper function which checks the users password)
 */
app.post('/login', async (req, res) => {
    try {
        // Find the user by email (converted to lowercase for consistency)
        const user = await User.findOne({ email: req.body.email.toLowerCase() });

        if (!user) {
            // No user found with the provided email
            return res.json("NoEmailExist");
        }

        // If user exists, call the auth function to verify password
        await auth(req, res, user);
        
    } catch (err) {
        console.log(err);
        res.redirect('/login'); // Redirect to login page if there's an error
    }
});


// const bcrypt = require('bcryptjs');

/**
 * This helper function checks the user's password from the database and handles errors.
 * It redirects the user to the login page in case of errors,
 * displays an error message if the password is wrong,
 * and logs the user in and redirects them to the homepage if the password is correct.
 * 
 * @param {*} req 
 * @param {*} res 
 * @param {*} user 
 */
async function auth(req, res, user) {
    try {
        // Compare the hashed password from the request body with the one stored in the database
        const isMatch = await bcrypt.compare(req.body.password, user.password);
        
        if (!isMatch) {
            // Passwords don't match
            return res.json({ error: "wrongPassword" });
        }
        
        // Password matched, log the user in and create session
        req.session.user = user;
        req.session.isLoggedIn = true;

        // Send the user data as a response
        res.json(user);
        
    } catch (err) {
        console.error(err);
        res.redirect('/login'); // Redirect to login page in case of any error
    }
}


/**
 * This post route will destory the user's session (log them out) and redirect them to login page.
 */
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.log(err);
    });
    res.redirect('/login')
})

/**
 * This post route will update the user's information from the database when a user wants to 
 * edit their profile and change their information including their password.
 * It also uses the isNotExisting helper function to help not allow
 * duplicate records in the datbase (two users having the same email, etc.)
 */
app.post('/editProfile', isLoggedIn, isNotExisting, async (req, res) => {
    let hashedPassword;
    var pass = req.session.user.password;
    var newpass;
    if (req.body.password == "") {
        newpass = pass;
    } else {
        hashedPassword = await bcrypt.hash(req.body.password, 10);
        newpass = hashedPassword;
    }
    User.updateOne({
            "_id": req.session.user._id
        }, {
            "firstName": req.body.firstname,
            "lastName": req.body.lastname,
            "username": req.body.username,
            "email": req.body.email,
            "phoneNum": req.body.phone,
            "password": newpass,
            "yearsExperience": req.body.yearsExperience,
            "sessionCost": req.body.sessionCost
        })
        .then((obj) => {
            return res.json("updated");
        })
        .catch((err) => {
            console.log(err);
        })
})

/**
 * 
 * This helper function checks to see if an email, phone number, or username exists 
 * or not from the database.
 * It returns an error message if an email, phone number, or username exists in the
 * database or else it returns next.
 * If there is an error finding the user it will load an error message else it will
 * destory the session and log the user out.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 */
async function isNotExisting(req, res, next) {
    var emailExists = await User.exists({
        email: req.body.email
    })
    var phoneExists = await User.exists({
        phoneNum: req.body.phone
    })
    var usernameExists = await User.exists({
        username: req.body.username
    })
    let userId = req.session.user._id;
    User.findById({
        _id: userId
    }, function (err, user) {
        if (err) console.log(err)
        if (user) {
            if (emailExists && req.body.email != user.email) {
                return res.json("existingEmail");
            } else if (phoneExists && req.body.phone != user.phoneNum) {
                return res.json("existingPhone")
            } else if (usernameExists && req.body.username != user.username) {
                return res.json("existingUsername")
            } else {
                return next();
            }
        } else {
            req.session.destroy();
            return res.json("logout");
        }
    })
}

/**
 * 
 * This helper function creates an account for user's who are therapists with
 * different fields to be saved in the database.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 */
async function createTherapistAccount(req, res) {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const new_user = new User({
        firstName: req.body.firstname,
        lastName: req.body.lastname,
        username: req.body.username,
        phoneNum: req.body.phone,
        userType: req.body.userType,
        yearsExperience: req.body.yearsExperience,
        sessionCost: req.body.sessionCost,
        email: req.body.email,
        password: hashedPassword
    });

    new_user.save()
        .then((result) => {
            res.json("login");
        });
}

/**
 * 
 * This helper function creates an account for user's who are patients
 * with different fields than the therapist user's to be saved in the
 * database.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 */
async function createPatientAccount(req, res) {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const new_user = new User({
        firstName: req.body.firstname,
        lastName: req.body.lastname,
        username: req.body.username,
        phoneNum: req.body.phone,
        userType: req.body.userType,
        email: req.body.email,
        password: hashedPassword
    });

    new_user.save()
        .then((result) => {
            res.json("login");
        });
}

/**
 * This route post allows users to sign up their account and store their information
 * on mongodb and stores the password as a hashed password. Uses isNotRegistered
 * helper function to ensure another user with given fields for
 * email, phone number, or username does not already exist.
 */
app.post("/sign-up", isNotRegistered, async (req, res) => {
    if (req.body.userType == "therapist") {
        return createTherapistAccount(req, res);
    } else {
        return createPatientAccount(req, res);
    }
})

/**
 * 
 * This helper function checks to see if a user with the email, phone number, or username
 * the user provided upon sign-up already exist in the database.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns a certain message corrosponding to which field already exists(email, phonenum, or username)
 * else if returns next.
 */
async function isNotRegistered(req, res, next) {
    var emailExists = await User.exists({
        email: req.body.email
    })
    var phoneExists = await User.exists({
        phoneNum: req.body.phone
    })
    var usernameExists = await User.exists({
        username: req.body.username
    })
    if (emailExists) {
        return res.json("existingEmail");
    } else if (phoneExists) {
        return res.json("existingPhone")
    } else if (usernameExists) {
        return res.json("existingUsername")
    } else {
        return next();
    }
}

//////Admin Dashboard\\\\\\

//MiddleWare

/**
 * 
 * This helper function checks to see if an admin is deleted
 * from the database from the admin dashboard is not the
 * last administrator in the database to ensure there is always
 * at least one admin.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns an error message if the admin to be deleted is the last administrator 
 * in the database else it returns next.
 */
function isNotLastAdminDelete(req, res, next) {
    if (req.body.previousUserType == 'admin') {
        User.count({
            userType: 'admin'
        }, (err, count) => {
            if (err) {
                console.log(err);
            } else if (count > 1) {
                return next();
            } else {
                return res.send('lastAdmin');
            }
        })
    } else {
        return next();
    }
}

/**
 * 
 * This helper function checks to see if an admin's usertype is editted
 * from the database from the admin dashboard is not the
 * last administrator in the database to ensure there is always
 * at least one admin.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns an error message if the admin to be editted is the last administrator 
 * in the database else it returns next.
 */
function isNotLastAdminEdit(req, res, next) {
    if (req.body.previousUserType == 'admin' && req.body.userType != 'admin') {
        User.count({
            userType: 'admin'
        }, (err, count) => {
            if (err) {
                console.log(err);
            } else if (count > 1) {
                return next();
            } else {
                return res.send('lastAdmin');
            }
        })
    } else {
        return next();
    }
}

//Routes

/**
 * This get route grabs all users from the database and returns them as a json object
 * so that they can be loaded in the admin dashboard.
 */
app.get('/getAllUsersData', isLoggedIn, isAdmin, setHeaders, (req, res) => {
    User.find({}, function (err, user) {
        if (err) {
            console.log(err);
        }
        if (!user) {}
        res.json(user);
    });
})

/**
 * This delete route allows administrators to delete a certain user from the database
 * using their id.
 */
app.delete('/deleteUser', isLoggedIn, isAdmin, isNotLastAdminDelete, async (req, res) => {
    User.deleteOne({
            _id: req.body.id
        })
        .then(function () {
            //if user is deleting themselves, delete session data
            if (req.body.id == req.session.user._id) {
                req.session.destroy();
            }
            res.send();
        }).catch(function (error) {
            console.log(error); // Failure
        });
})

/**
 * This delete route allows users to delete their profiles from the database (Delete account).
 */
app.delete('/deleteUserProfile', isLoggedIn, isNotLastAdminDelete, async (req, res) => {
    User.deleteOne({
            _id: req.session.user._id
        })
        .then(function () {
            req.session.destroy();
            res.send();
        }).catch(function (error) {
            console.log(error); // Failure
        });
})

/**
 * 
 * This helper function checks to see if the given email, phone number, or username
 * to be editted does not already exist in the database for administrators when they
 * edit a certain users information.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 */
async function isNotExistingAdmin(req, res, next) {
    var emailExists = await User.exists({
        email: req.body.email
    })
    var phoneExists = await User.exists({
        phoneNum: req.body.phone
    })
    var usernameExists = await User.exists({
        username: req.body.username
    })

    let userId = req.body.id;
    User.findById({
        _id: userId
    }, function (err, user) {
        if (err) console.log(err)
        if (user) {
            if (emailExists && req.body.email != user.email) {
                return res.send("existingEmail");
            } else if (phoneExists && req.body.phone != user.phoneNum) {
                return res.send("existingPhone")
            } else if (usernameExists && req.body.username != user.username) {
                return res.send("existingUsername")
            } else {
                return next();
            }
        } else {
            res.send("unexistingUser")
        }
    })
}

/**
 * 
 * This helper function updates a user's account that is a therapist
 * with certain fields that belong to the therapist user's in the
 * databsae.
 * 
 * @param {*} req as request object
 * @param {*} res as response object 
 */
function updateTherapist(req, res) {
    User.updateOne({
            "_id": req.body.id
        }, {
            "firstName": req.body.firstname,
            "lastName": req.body.lastname,
            "username": req.body.username,
            "email": req.body.email,
            "phoneNum": req.body.phone,
            "userType": req.body.userType,
            "yearsExperience": req.body.yearsExperience,
            "sessionCost": req.body.sessionCost
        })
        .then((obj) => {
            if (req.session.user._id == req.body.id && req.body.userType != req.session.user.userType)
                req.session.destroy();
            return res.send("updatedWithoutPassword");
        })
        .catch((err) => {
            console.log(err);
        })
}

/**
 * 
 * This helper function updates a user's account that is a patient
 * with certain fields that belong to the patient user's in the 
 * database.
 * 
 * @param {*} req as request object
 * @param {*} res as response object 
 */
async function updatePatient(req, res) {
    User.updateOne({
            "_id": req.body.id
        }, {
            $unset: {
                "yearsExperience": "",
                "sessionCost": ""
            },
            "firstName": req.body.firstname,
            "lastName": req.body.lastname,
            "username": req.body.username,
            "email": req.body.email,
            "phoneNum": req.body.phone,
            "userType": req.body.userType
        })
        .then((obj) => {
            if (req.session.user._id == req.body.id && req.body.userType != req.session.user.userType)
                req.session.destroy();
            return res.send("updatedWithoutPassword");
        })
        .catch((err) => {
            console.log(err);
        })
}

/**
 * 
 * Helper function that updates a therapist's user account AND
 * updates their password in the database.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 */
async function updateTherapistWithPassword(req, res) {
    var hashedPassword = await bcrypt.hash(req.body.password, 10);
    User.updateOne({
            "_id": req.body.id
        }, {
            "firstName": req.body.firstname,
            "lastName": req.body.lastname,
            "username": req.body.username,
            "email": req.body.email,
            "phoneNum": req.body.phone,
            "userType": req.body.userType,
            "yearsExperience": req.body.yearsExperience,
            "sessionCost": req.body.sessionCost,
            "password": hashedPassword
        })
        .then((obj) => {
            if (req.session.user._id == req.body.id && req.body.userType != req.session.user.userType)
                req.session.destroy();
            return res.send("updatedWithPassword");
        })
        .catch((err) => {
            console.log(err);
        })

}

/**
 * 
 * This helper function updates a patient's user account AND
 * updates their password in the database.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 */
async function updatePatientWithPassword(req, res) {
    var hashedPassword = await bcrypt.hash(req.body.password, 10);
    User.updateOne({
            "_id": req.body.id
        }, {
            $unset: {
                "yearsExperience": "",
                "sessionCost": ""
            },
            "firstName": req.body.firstname,
            "lastName": req.body.lastname,
            "username": req.body.username,
            "email": req.body.email,
            "phoneNum": req.body.phone,
            "userType": req.body.userType,
            "password": hashedPassword
        })
        .then((obj) => {
            if (req.session.user._id == req.body.id && req.body.userType != req.session.user.userType)
                req.session.destroy();
            return res.send("updatedWithPassword");
        })
        .catch((err) => {
            console.log(err);
        })
}

/**
 * This put route allows admins to edit a cetain users information in the database from
 * the admin dashboard.
 */
app.put('/editUser', isLoggedIn, isAdmin, isNotExistingAdmin, isNotLastAdminEdit, (req, res) => {
    if (req.body.userType == "therapist") {
        if (req.body.password != "") {
            return updateTherapistWithPassword(req, res);
        } else {
            return updateTherapist(req, res);
        }
    } else {
        if (req.body.password != "") {
            return updatePatientWithPassword(req, res);
        } else {
            return updatePatient(req, res)

        }
    }
})



/**
 * This post route allows amdministrators to create a user from the admin panel.
 */
app.post("/createUser", isLoggedIn, isAdmin, isNotRegistered, (req, res) => {
    if (req.body.userType == "therapist") {
        return createTherapistAccount(req, res);
    } else {
        return createPatientAccount(req, res);
    }
})

//Checkout

/**
 * This post route allows users to add a therapy session to their
 * cart so that they can checkout later.
 * It checks to see if they already have something in their cart,
 * or a session that is already active and returns an error message.
 * Else it adds the session to their cart and the database with 
 * an "active" status.
 */
app.post('/addToCart', isLoggedIn, async (req, res) => {
    var cartExists = await Cart.exists({
        userId: req.session.user._id,
        status: "active"
    })
    if (cartExists) {
        return res.send("cartExists");
    }
    //Check if user has a current valid session with another therapist
    var currentTime = new Date();
    var orderExists = await Cart.exists({
        userId: req.session.user._id,
        status: "completed",
        expiringTime: {
            $gt: currentTime
        }
    })
    if (orderExists) {
        return res.send("orderExists");
    }
    const new_cart = new Cart({
        orderId: "MM" + Math.floor((Math.random() * 1500000000) + 1000000000),
        therapist: req.body.therapist,
        userId: req.session.user._id,
        status: "active"
    });
    new_cart.save()
        .then((result) => {});
    res.send();
})

/**
 * This get route checks the status of a shopping cart
 * to ensure the user does not already have an item
 * in their shopping cart.
 */
app.get('/checkStatus', isLoggedIn, (req, res) => {
    Cart.findOne({
        userId: req.session.user._id,
        status: "active"
    }, function (err, cart) {
        if (err) {
            console.log(err);
        }
        if (!cart) {
            res.send();
        } else {
            res.json(cart);
        }
    });
})

/**
 * This post route finds and grabs a certain therapist by their id and returns
 * their information.
 */
app.post('/getTherapistInfo', isLoggedIn, (req, res) => {
    var therapistInfo;
    User.findById({
        _id: req.body.therapistId
    }, function (err, user) {
        if (err) console.log(err)
        if (!user) {
            return res.redirect('/')
        } else {
            therapistInfo = {
                firstName: user.firstName,
                lastName: user.lastName,
                yearsExperience: user.yearsExperience,
                sessionCost: user.sessionCost,
                profileImg: user.profileImg
            }
            res.json(therapistInfo);
        }
    })
})

/**
 * This delete route deletes the item that exists in the users
 * shopping cart and changes the status from active to deleted.
 */
app.delete('/deleteCart', isLoggedIn, async (req, res) => {
    Cart.updateOne({
        userId: req.session.user._id,
        status: "active"
    }, {
        status: "deleted"
    }).then((obj) => {
        res.send()
    }).catch(function (error) {
        console.log(error);
    })
})

// MiddleWare for checkout
/**
 * 
 * This helper function checks to see if a user have already used their
 * free trial, and if they have it will return an error message.
 * 
 * @param {*} req as request object
 * @param {*} res as response object
 * @param {*} next executes the middleware succeeding the current middleware.
 * @returns an error message if trail is already used, or else it returns next to allow user
 * to use their free trial.
 */
// async function usedTrial(req, res, next) {
//     var trialStatus;
//     if (req.body.cartPlan == "freePlan") {
//         trialStatus = await User.exists({
//             _id: req.session.user._id,
//             usedTrial: true
//         })
//     }
//     if (trialStatus) {
//         return res.json({
//             errorMsg: "You have already used your free trial."
//         });
//     } else {
//         return next();
//     }
// }

// /**
//  * 
//  * This helper function sends a formatted email to the patient's email address
//  * which is fetched from the database.
//  * 
//  * @param {*} transporter as function
//  * @param {*} patientInfo as object
//  * @param {*} therapistInfo as object
//  * @param {*} cartInfo as object
//  */
// function sendPatientEmail(transporter, patientInfo, therapistInfo, cartInfo){
//     const mailPatient = {
//         from: process.env.MAIL_USER,
//         to: patientInfo.email,
//         subject: 'Thank you for purchasing a session with MyMind!',
//         html: `<div style="display:flex;width:100%;background:#09C5A3;"><img src="cid:logo" style="width:15%;margin:auto;padding:1.5rem 1rem 1rem;object-fit:contain;object-position:center center;"></div>
//         <div style="display:flex;width:100%;background:#09C5A3;margin-bottom:2rem;"><h1 style="text-align:center;color:#FFF;text-transform:capitalize;font-size:2rem;font-weight:700;padding-top:1rem;padding-bottom:1rem;width: 100%;">Thank you for purchasing!</h1></div>
//         <p style="font-size:14px;color:#000;">We have activated a therapy session with ${therapistInfo.firstName} ${therapistInfo.lastName}. Your session will expire at ${new Date(cartInfo.expiringTime).toLocaleString('en-CA', { hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: true })}, and you can view your cart history at our Order History page at any time! We hope you have a wonderful session, thank you for your time and support. To start your journey, please login to your account and visit <a style="color:#09C5A3;text-decoration:none;font-weight:700;" href="https://mymindweb.herokuapp.com/" target="_blank">MyMind</a> to start your journey!</p><p style="font-size:14px;color:#000;">Cheers</p>`,
//         attachments: [{
//             filename: 'logo.png',
//             path: __dirname + '/public/images/logo.png',
//             cid: 'logo'
//         }]
//     };
//     transporter.sendMail(mailPatient, function (err, info) {
//         if (err) console.log(err)
//     });
// }

// /**
//  * 
//  * This helper function sends a formatted email to the therapist's email address
//  * which is fetched from the database.
//  * 
//  * @param {*} transporter as function
//  * @param {*} patientInfo as object
//  * @param {*} therapistInfo as object
//  * @param {*} cartInfo as object
//  */
// function sendTherapistEmail(transporter, patientInfo, therapistInfo, cartInfo){
//     let sessionLength;
//     if (cartInfo.timeLength == 'yearPlan') sessionLength = 15;
//     else if (cartInfo.timeLength == 'threeMonthPlan') sessionLength = 10;
//     else if (cartInfo.timeLength == 'monthPlan') sessionLength = 5;
//     else sessionLength = 3;

//     const mailTherapist = {
//         from: process.env.MAIL_USER,
//         to: therapistInfo.email,
//         subject: 'You have a new patient waiting for you!',
//         html: `<div style="display:flex;width:100%;background:#09C5A3;"><img src="cid:logo" style="width:15%;margin:auto;padding:1.5rem 1rem 1rem;object-fit:contain;object-position:center center;"></div>
//         <div style="display:flex;width:100%;background:#09C5A3;margin-bottom:2rem;"><h1 style="text-align:center;color:#FFF;text-transform:capitalize;font-size:2rem;font-weight:700;padding-top:1rem;padding-bottom:1rem;width: 100%;">You have a new patient waiting for you!</h1></div>
//         <p style="font-size:14px;color:#000;">Your patient, ${patientInfo.firstName} ${patientInfo.lastName} has purchased a session with you for ${sessionLength} mins and is waiting to chat! Please get in contact with him as soon as possible!</p><p style="font-size:14px;color:#000;">Cheers</p>`,
//         attachments: [{
//             filename: 'logo.png',
//             path: __dirname + '/public/images/logo.png',
//             cid: 'logo'
//         }]
//     }
//     transporter.sendMail(mailTherapist, function (err, info) {
//         if (err) console.log(err)
//     });
// }

// /**
//  * 
//  * This helper function sends an email confirmation to the users email and the therapists
//  * email and thank them for their purchase.
//  * 
//  * @param {*} userId as user's ID
//  * @param {*} therapistId as therapist's ID
//  * @param {*} cartInfo as an object that contains the order information
//  */
// async function sendEmails(userId, therapistId, cartInfo) {
//     const transporter = nodemailer.createTransport({
//         service: 'hotmail',
//         auth: {
//             user: process.env.MAIL_USER,
//             pass: process.env.MAIL_PASS
//         }
//     });

//     let patientInfo = await User.findById({
//         _id: userId
//     });
//     let therapistInfo = await User.findById({
//         _id: therapistId
//     });

//     sendPatientEmail(transporter, patientInfo, therapistInfo, cartInfo)

//     // email to therapist -- timeout because hotmail has a limit of requests/second
//     setTimeout(() => {
//         sendTherapistEmail(transporter, patientInfo, therapistInfo, cartInfo)
//     }, 2000);
// }

// /**
//  * This post route confirms an order when user confirms the item in their shopping cart
//  * and starts their session with the chosen therapist.
//  */
// app.post('/confirmCart', isLoggedIn, usedTrial, isTherapistAvailable, (req, res) => {
//     const currentDate = Date.now();
//     Cart.findOneAndUpdate({
//         userId: req.session.user._id,
//         status: "active"
//     }, {
//         status: "completed",
//         $set: {
//             purchased: currentDate,
//             expiringTime: req.body.timeLengthforUse,
//             cost: req.body.totalPrice
//         }
//     }, {
//         new: true
//     }).then((cart) => {
//         sendEmails(req.session.user._id, req.body.therapistID, cart)
//         incrementTherapistSessionNum(req.session.user._id);
//         res.send(cart);
//     }).catch(function (error) {
//         console.log(error);
//     })
//     if (req.body.cartPlan == 'freePlan') {
//         User.updateOne({
//             _id: req.session.user._id
//         }, {
//             usedTrial: true
//         }).then((obj) => {}).catch(function (error) {
//             console.log(error);
//         })
//     }
// })

// /**
//  * This helper function increments the number of session for
//  * each therapist when a order is confirmed so that the therapist
//  * can be loaded by popularity in the home page.
//  * @param {*} userID as therapists ID
//  */
// function incrementTherapistSessionNum(userID) {
//     Cart.find({
//         userId: userID,
//         status: "completed"
//     }, function (err, carts) {
//         if (err) {
//             console.log(err);
//         }
//         if (carts) {
//             const sortedCart = carts.sort((a, b) => b.purchased - a.purchased)
//             var therapistID = sortedCart[0].therapist
//             User.updateOne({
//                 _id: therapistID
//             }, {
//                 $inc: {
//                     numSessions: 1
//                 }
//             }).then(() => {}).catch(function (error) {
//                 console.log(error);
//             })
//         }
//     });
// }

// /**
//  * This put route updates the user's shopping cart when they
//  * change the time length(eg. 1month to 1 year).
//  */
// app.put('/updateCart', isLoggedIn, async (req, res) => {
//     Cart.updateOne({
//         userId: req.session.user._id,
//         status: "active"
//     }, {
//         timeLength: req.body.timeLength
//     }).then((obj) => {
//         res.send(obj)
//     }).catch(function (error) {
//         console.log(error);
//     })
// })

// /**
//  * This get route finds all completed or refunded orders for a 
//  * certain user and returns them as an object array.
//  */
// app.get('/getPreviousPurchases', isLoggedIn, (req, res) => {
//     Cart.find({
//         userId: req.session.user._id,
//         $or: [{
//             status: "completed",
//         }, {
//             status: "refunded",
//         }]
//     }, function (err, carts) {
//         if (err) {
//             console.log(err);
//         }
//         if (carts) {
//             res.json(carts);
//         }
//     });
// })

// /**
//  * This get route finds all completed or refunded orders for a 
//  * certain user and returns them as an object array for a therapist.
//  */
// app.get('/getPreviousPatients', isLoggedIn, (req, res) => {
//     Cart.find({
//         therapist: req.session.user._id,
//         $or: [{
//             status: "completed",
//         }, {
//             status: "refunded",
//         }]
//     }, function (err, carts) {
//         if (err) {
//             console.log(err);
//         }
//         if (carts) {
//             res.json(carts);
//         }
//     });
// })

// /**
//  * This get route finds the most recent purchase and returns it as an object.
//  */
// app.get('/recentPurchase', isLoggedIn, (req, res) => {
//     Cart.find({
//         userId: req.session.user._id,
//         status: "completed"
//     }, function (err, carts) {
//         if (err) {
//             console.log(err);
//         }
//         if (carts) {
//             const sortedCart = carts.sort((a, b) => b.purchased - a.purchased)
//             return res.json(sortedCart[0])
//         }
//     });
// })

// /**
//  * 
//  * This helper function checks if an active session exists, if it
//  * does it returns an error message to the user when they try
//  * to purchase another session with the same or a different
//  * therapist whilst they have an active one.
//  * 
//  * @param {*} req as request object
//  * @param {*} res as response object
//  * @param {*} sortedCart as object array
//  */
// function getSessionData(req, res, sortedCart) {
//     var therapistName;
//     var errorMessageVariables;
//     User.findOne({
//         _id: sortedCart[0].therapist
//     }, function (err, user) {
//         if (err) console.log(err)
//         if (user) {
//             therapistName = user.firstName + " " + user.lastName
//             errorMessageVariables = {
//                 cost: sortedCart[0].cost,
//                 purchased: sortedCart[0].expiringTime,
//                 therapistName: therapistName
//             };
//             return res.json(errorMessageVariables)
//         }
//     })
// }


// /**
//  * This get route checks to see if there is an active session for the user 'patient'
//  * by checking the expiring time on the order (time length they choose when placing an order).
//  */
// app.get('/activeSession', isLoggedIn, (req, res) => {
//     var currentTime = new Date();
//     Cart.find({
//         userId: req.session.user._id,
//         status: "completed",
//         expiringTime: {
//             $gt: currentTime
//         }
//     }, function (err, carts) {
//         if (err) {
//             console.log(err);
//         }
//         if (carts.length > 0) {
//             const sortedCart = carts.sort((a, b) => b.purchased - a.purchased);
//             return getSessionData(req, res, sortedCart);
//         } else {
//             return res.json("NoActiveSession");
//         }
//     })
// })

// /**
//  * This post route allows a user to refund an active order.
//  */
// app.post('/refundOrder', isLoggedIn, (req, res) => {
//     var currentTime = new Date();
//     Cart.updateOne({
//         userId: req.session.user._id,
//         status: "completed",
//         expiringTime: {
//             $gt: currentTime
//         }
//     }, {
//         expiringTime: currentTime,
//         status: "refunded"
//     }).then((obj) => {
//         res.send(obj)
//     }).catch(function (error) {
//         console.log(error);
//     })
// })


//Live Chat
//record ids of users connected to a room
let users = [];

//Creates connection between server and client
/**
 * This io function starts a connection for socket and connects 
 * to the mongodb to store all messages sent by the patient and therapist.
 * It also joins two users (the patient and the therapist) to a room
 * to start their chatting session privately.
 */
// io.on('connection', (socket) => {
//     var userId;
//     var orderID;

//     socket.on("chat message", function (msg, room) {

//         //broadcast message to everyone in port:8000 except yourself.
//         socket.to(room).emit("chat message", {
//             message: msg
//         });

//         //save chat to the database
//         let connect = mongoose.connect(process.env.DATABASE_URL, {
//             useNewUrlParser: true,
//             useUnifiedTopology: true
//         })
//         connect.then(db => {
//             let chatMessage = new Chat({
//                 message: msg,
//                 sender: userId,
//                 orderId: orderID
//             });

//             chatMessage.save();
//         });

//     });

//     socket.on("join-room", function (room, senderId) {
//         socket.join(room);
//         orderID = room;
//         userId = senderId;
//         users.push(senderId);
//         socket.to(room).emit("connected", senderId)
//     })

//     socket.on('disconnect', () => {
//         if (!userId) return;

//         var index = users.indexOf(userId);
//         users.splice(index, 1);

//         let newIndex = users.indexOf(userId);
//         if (newIndex == -1) {
//             socket.to(orderID).emit("disconnected")
//         }
//     })

//     socket.on('check-status', (otherId, callback) => {
//         if (!otherId) return;

//         var index = users.indexOf(otherId);
//         if (index > -1) {
//             callback();
//         }
//     })

// });


// /**
//  * 
//  * This helper function fetches and returns a therapist's information
//  * to the chat page to display their information on the chat page in order
//  * to send messages.
//  * 
//  * @param {*} req as request object
//  * @param {*} res as response object
//  * @param {*} carts as object array
//  */
// function getTherapistChat(req, res, carts){
//     var orderId = carts.orderId;
//     var purchased = carts.expiringTime;
//     var therapistId = carts.therapist;
//     var userId = carts.userId;
//     var chatInfo;
//     User.findOne({
//         _id: userId
//     }, function (err, user) {
//         if (err) console.log(err)
//         if (user) {
//             chatInfo = {
//                 purchased: purchased,
//                 orderId: orderId,
//                 therapistId: therapistId,
//                 userId: userId,
//                 name: user.firstName + " " + user.lastName,
//                 phone: user.phoneNum,
//                 image: user.profileImg,
//                 sender: therapistId,
//                 currentId: req.session.user._id,
//                 other: userId
//             };
//             return res.json(chatInfo)
//         }
//     })
// }

// /**
//  * 
//  * This helper function fetcehes and returns a patient's information
//  * to the chat page to display their information on the chat page in order
//  * to send messages.
//  * 
//  * @param {*} req as request object
//  * @param {*} res as response object
//  * @param {*} carts as object array
//  */
// function getPatientChat(req, res, carts){
//     var orderId = carts.orderId;
//     var purchased = carts.expiringTime;
//     var therapistId = carts.therapist;
//     var userId = carts.userId;
//     var chatInfo;
//     User.findOne({
//         _id: therapistId
//     }, function (err, user) {
//         if (err) console.log(err)
//         if (user) {
//             chatInfo = {
//                 purchased: purchased,
//                 orderId: orderId,
//                 therapistId: therapistId,
//                 userId: userId,
//                 name: user.firstName + " " + user.lastName,
//                 phone: user.phoneNum,
//                 image: user.profileImg,
//                 sender: userId,
//                 currentId: req.session.user._id,
//                 other: therapistId
//             };
//             return res.json(chatInfo)
//         }
//     })
// }

// // /**
// //  * 
// //  * This function calls the helper functions for patient or therapist
// //  * based on the user type that is logged in.
// //  * 
// //  * @param {*} req as request object
// //  * @param {*} res as response object
// //  * @param {*} carts as object array
// //  */
// // function getOtherChat(req, res, carts){
// //     User.findOne({
// //         _id: req.session.user._id
// //     }, function (err, user) {
// //         if (err) console.log(err)
// //         if (user) {
// //             if (user.userType == 'therapist') {
// //                 return getTherapistChat(req, res, carts)
// //             } else {
// //                 return getPatientChat(req, res, carts);
// //             }
// //         } else {
// //             return res.json("InvalidUser")
// //         }
// //     })
// // }

// // /**
// //  * This get route checks to see if an active chat session already exists.
// //  */
// // app.get('/activeChatSession', async (req, res) => {
// //     try {
// //         // Check if the user is logged in
// //         if (!req.session.isLoggedIn) {
// //             return res.json({ message: "notLoggedIn" });
// //         }

// //         const currentTime = new Date();

// //         // Find a cart with either userId or therapist matching the session user ID
// //         const cart = await Cart.findOne({
// //             $or: [
// //                 { userId: req.session.user._id },
// //                 { therapist: req.session.user._id }
// //             ],
// //             status: "completed",
// //             expiringTime: { $gt: currentTime }
// //         });

// //         if (cart) {
// //             // Pass the cart data to getOtherChat function for further processing
// //             return getOtherChat(req, res, cart);
// //         } else {
// //             // No active chat session found
// //             return res.json({ message: "NoActiveSession" });
// //         }
// //     } catch (err) {
// //         // Log and return error if something goes wrong
// //         console.error("Error in /activeChatSession:", err);
// //         return res.status(500).json({ error: "Internal server error" });
// //     }
// // });


// /**
//  * This post route finds and loads all messages from the dabatase
//  * in an ascending order based on when it was sent.
//  */
// app.post('/loadMsgs', function (req, res) {
//     Chat.find({
//         orderId: req.body.orderId
//     }, function (err, chats) {
//         if (err) {
//             console.log(err);
//         }
//         if (chats) {
//             res.json(chats);
//         }
//     }).sort({
//         createdAt: 'asc'
//     });

// })

/**
 * This get route renders 404.html page.
 */
app.get("*", (req, res) => {
    res.sendFile(path.resolve('html/404.html'))
});

/**
 * This allows the server to listen for a certain port.
 */
server.listen(process.env.PORT || 8000, () => {
    console.log(`listening on port ${process.env.PORT || 8000} `)
});
