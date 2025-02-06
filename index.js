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
const { initializeApp } = require("firebase/app");
const { getStorage } = require("firebase/storage");
const MongoStore = require('connect-mongo');
const fetch = globalThis.fetch;

const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const CX = process.env.GOOGLE_SEARCH_ENGINE_ID;

const firebaseConfig = 
{
    apiKey: process.env.GOOGLE_API_KEY,
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

// Connection URI
const uri = `mongodb+srv://topxAdmin:${process.env.MONGO_PASSWORD}@topx.c8dwz.mongodb.net/?retryWrites=true&w=majority&appName=TopX`;

// Use middlewares
app.use(cors({
    origin: 'http://127.0.0.1:5500', // Adjust this based on your frontend
    credentials: true,
}));
app.use(bodyParser.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: uri }),
    cookie: { secure: false,
            sameSite: "lax",
    } // Set to true if using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());


// Multer setup: Store file in memory before uploading
const upload = multer({ storage: multer.memoryStorage() });

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
        console.log("deserializing user with id: " + id);
        await client.connect();
        const db = client.db('users');
        const users = db.collection('profiles');
        const user = await users.findOne({ _id: ObjectId.createFromHexString(id.toString()) });
        
        if (!user) return done(null, false);
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
            friends: [],
            profilePicture: ""
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
    const { _id, email, username, iconUrl } = req.user;
    res.json({
        message: 'success',
        user: { _id, email, username, iconUrl }
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.logout(err => {
        if (err) return res.status(500).json({ message: 'Logout failed', error: err });
        res.json({ message: 'Logged out successfully' });
    });
});

app.post("/uploadProfilePicture", upload.single("image"), async (req, res) => 
    {
        console.log("📤 Checking authentication for route: /uploadProfilePicture");
        console.log("Session:", req.session);
        console.log("User:", req.user);
    
        if (!req.isAuthenticated()) 
        {
            console.error("❌ User is not authenticated.");
            return res.status(401).json({ message: "Unauthorized" });
        }
    
        if (!req.file) 
        {
            return res.status(400).json({ message: "No file uploaded" });
        }
    
        try 
        {
            const userId = req.user._id.toString();
            const storageRef = ref(storage, `profile_pictures/${userId}.jpg`);
    
            // Upload file to Firebase Storage
            await uploadBytes(storageRef, req.file.buffer);
    
            // Get the image's public URL
            const imageUrl = await getDownloadURL(storageRef);
    
            // Update the user's profilePicture in the database
            await client.connect();
            const db = client.db('users');
            const users = db.collection('profiles');
    
            await users.updateOne(
                { _id: ObjectId.createFromHexString(userId.toString()) },
                { $set: { profilePicture: imageUrl } }
            );
    
            console.log("✅ Profile picture updated in database:", imageUrl);
    
            res.json({ imageUrl });
        } 
        catch (error) 
        {
            console.error("❌ Error uploading file:", error);
            res.status(500).json({ message: "Upload failed", error: error.message || error });
        }
    });
    
// Route to get all users in the db
app.get('/getAllUsers', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            await client.connect();
            const db = client.db('users');
            const users = db.collection('profiles');
            const allUsers = await users.find().toArray();
            res.json({ message: "success", users: allUsers });
        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to send friend request
app.post('/sendFriendRequest', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('users');
            const notifications = db.collection('notifications');

            //check existing friend requests
            const existingRequest = await notifications.find({ $or: [ { sender: req.user._id }, { receiver: req.user._id } ] }).toArray();

            if (existingRequest.length === 0) {
                let friendRequest = {
                    sender: ObjectId.createFromHexString(req.user._id.toString()),
                    receiver: ObjectId.createFromHexString(req.body.receiver),
                    createdTimestamp: new Date(),
                    type: 'friendRequest'
                }
                const result = await notifications.insertOne(friendRequest);
                friendRequest._id = result.insertedId;
                res.json({ message: "success", friendRequest: friendRequest });
            } else {
                console.log(existingRequest);
                res.json({ message: "friend request already exists" });
            }

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to accept friend request
app.post('/acceptFriendRequest', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('users');
            const notifications = db.collection('notifications');
            const users = db.collection('users');

            //check if request exists
            const existingRequest = await notifications.findOne({ _id: ObjectId.createFromHexString(req.body.requestId.toString()) });

            if (existingRequest === null || existingRequest === undefined) {
                res.json({ message: "friend request doesn't exist" });
            } else if ( req.user._id.toString() !== existingRequest.receiver.toString() ) {
                res.json({ message: "user isn't the intended recipient" });
            } else {
                await users.updateOne({ _id: existingRequest.sender }, { $push: { friends: ObjectId.createFromHexString(req.user._id.toString()) } });
                await users.updateOne({ _id: ObjectId.createFromHexString(req.user._id.toString()) }, { $push: { friends: existingRequest.sender } });
                await notifications.deleteOne({ _id: existingRequest._id });

                let updatedFriendsList = req.user.friends;
                updatedFriendsList.push(existingRequest.sender);

                res.json({ message: "success", updatedFriendsList: updatedFriendsList });
            }

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});
    

// Route to check authentication status
app.get('/authStatus', (req, res) => 
    {
        console.log("Session during authStatus:", req.session);
        if (req.isAuthenticated()) 
        {
            const user = req.user;
            res.json({
                authenticated: true,
                user: {
                    _id: user._id,
                    email: user.email,
                    username: user.username,
                    profilePicture: user.profilePicture || 'assets/images/User Icon.png'
                }
            });
        } 
        else 
        {
            res.json({ authenticated: false });
        }
    });

app.get('/scrape-images', async (req, res) => {
    const query = req.query.q;
    if (!query) {
        console.error("Missing search query");
        return res.status(400).json({ error: 'Missing search query' });
    }

    try {
        const url = `https://www.googleapis.com/customsearch/v1?q=${encodeURIComponent(
            query
        )}&cx=${CX}&searchType=image&num=1&key=${GOOGLE_API_KEY}`; // Limit to 1 result

        const response = await fetch(url);
        const data = await response.json();

        if (data.error) {
            console.error("Error from Google API:", data.error);
            return res.status(500).json({ error: data.error.message });
        }

        if (data.items && data.items.length > 0) {
            const imageUrl = data.items[0].link; // Get the first image
            res.json({ image: imageUrl });
        } else {
            console.error("No images found:", data);
            res.status(404).json({ error: 'No images found' });
        }
    } catch (error) {
        console.error("Error in /scrape-images:", error);
        res.status(500).json({ error: 'Failed to fetch image' });
    }
});

app.get("/", async (req, res) => {
    res.send({ serverStatus: "running" });
});

app.listen(8080, () => {
    console.log("Server is running on port 8080");
});
