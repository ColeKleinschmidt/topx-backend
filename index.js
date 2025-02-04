// Import dependencies
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion, ObjectId, Timestamp } = require('mongodb');
require('dotenv').config();

// Initialize express app
const app = express();

// Use middlewares
app.use(cors({
    origin: 'http://127.0.0.1:5500', // Adjust this based on your frontend
    credentials: true
}));
app.use(bodyParser.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());

// Connection URI
const uri = `mongodb+srv://topxAdmin:${process.env.MONGO_PASSWORD}@topx.c8dwz.mongodb.net/?retryWrites=true&w=majority&appName=TopX`;

// Create a MongoClient
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Define Passport Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        await client.connect();
        const db = client.db('users');
        const users = db.collection('profiles');
        const user = await users.findOne({ email });

        if (!user) {
            console.log("no user found with email: " + email);
            return done(null, false, { message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log("given password inccorrect for user with email: " + email);
            return done(null, false, { message: 'Incorrect password' });
        }

        console.log("user logged in successfully with email: " + email);
        return done(null, user);
    } catch (error) {
        console.log(error);
        return done(error);
    }
}));

// Serialize and Deserialize user
passport.serializeUser((user, done) => {
    console.log('trying to make it work');
    done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
    console.log('trying to make it work');
    try {
        await client.connect();
        const db = client.db('users');
        const users = db.collection('profiles');
        const user = await users.findOne({ _id: new ObjectId(id) });
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Route to create an account
app.post('/createAccount', async (req, res) => {
    const { email, password, username } = req.body;
    console.log("creating new account with email: " + email + " and username: " + username);

    if (!email || !password || !username) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        await client.connect();
        const db = client.db('users');
        const users = db.collection('profiles');

        const existingUser = await users.findOne({ email });
        if (existingUser) {
            console.log("user with email " + email + " already exists");
            return res.status(400).json({ message: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { 
            email, 
            password: hashedPassword, 
            username,
            createdTimestamp: new Date(),
            lastLoginTimestamp: new Date(), 
        };
        console.log("inserting new user into database: ");
        console.log(newUser);

        const result = await users.insertOne(newUser);
        res.status(201).json({ message: 'Account created successfully', userId: result.insertedId });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

// Login route
app.post('/login', passport.authenticate('local'), (req, res) => {
    res.json({ message: 'Logged in successfully', user: req.user });                                                                                                                    
});

// Logout route
app.post('/logout', (req, res) => {
    req.logout(err => {
        if (err) return res.status(500).json({ message: 'Logout failed', error: err });
        res.json({ message: 'Logged out successfully' });
    });
});

// Route to send a friend request
app.post('/logout', (req, res) => {
    const { friendUserID } = req.body;

    const newFriendRequest = {
        type: 'friend request',
        sendingUser: req.user._id,
        receivingUser: friendUserID,
        timestamp: new Date(),
    }
});

// Route to check authentication status
app.get('/authStatus', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ authenticated: true, user: req.user });
    } else {
        res.json({ authenticated: false });
    }
});

app.get("/", async (req, res) => {
    res.send({ serverStatus: "running" });
});

app.listen(8080, () => {
    console.log("Server is running on port 8080");
});
