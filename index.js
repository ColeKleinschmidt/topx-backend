// Import dependencies
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const { initializeApp } = require("firebase/app");
const { getStorage } = require("firebase/storage");

const firebaseConfig = 
{
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID,
    measurementId: process.env.FIREBASE_MEASUREMENT_ID
};

const firebaseApp = initializeApp(firebaseConfig);
const storage = getStorage(firebaseApp);
const { ref, uploadBytes, getDownloadURL } = require("firebase/storage");
const multer = require("multer");

// Initialize express app
const app = express();

// Use middlewares
app.use(cors({
    origin: 'http://localhost:5173', // Adjust this based on your frontend
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


// Multer setup: Store file in memory before uploading
const upload = multer({ storage: multer.memoryStorage() });

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
    done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
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

app.post("/uploadProfilePicture", upload.single("image"), async (req, res) => 
    {
        if (!req.isAuthenticated()) 
        {
            return res.status(401).json({ message: "Unauthorized" });
        }
    
        if (!req.file) 
        {
            return res.status(400).json({ message: "No file uploaded" });
        }
    
        try 
        {
            const userId = req.isAuthenticated() ? req.user._id.toString() : "testUserId";
            const storageRef = ref(storage, `profile_pictures/${userId}.jpg`);
    
            // Upload file to Firebase Storage
            await uploadBytes(storageRef, req.file.buffer);
    
            // Get the image's public URL
            const imageUrl = await getDownloadURL(storageRef);
    
            res.json({ imageUrl });
        } 
        catch (error) 
        {
            console.error("Error uploading file:", error);
            res.status(500).json({ message: "Upload failed", error: error.message || error });
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
