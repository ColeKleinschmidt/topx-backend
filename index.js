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
const { initializeApp } = require('firebase/app');
const { getStorage } = require('firebase/storage');
const MongoStore = require('connect-mongo');
const fetch = globalThis.fetch;
const path = require('path');

const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const CX = process.env.GOOGLE_SEARCH_ENGINE_ID;

const IMAGE_NOT_FOUND = "https://upload.wikimedia.org/wikipedia/commons/f/fc/No_picture_available.png";

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
        
        if (!user) return done(null, false, { redirect: '/' });
        done(null, user);
    } catch (error) {
        done(error);
    }
});

const scrapeImages = async (query) => {
    const url = `https://www.googleapis.com/customsearch/v1?q=${encodeURIComponent(
        query
    )}&cx=${CX}&searchType=image&num=1&key=${GOOGLE_API_KEY}`; // Limit to 1 result

    const response = await fetch(url);
    const data = await response.json();
    return data;
}

const addItemToDb = async (item, req) => {
    try {
        //connect to collection
        await client.connect();
        const db = client.db('lists');
        const items = db.collection('items');

        console.log('adding new item to db');
        let newItem = item;
        newItem.createdTimestamp = new Date();
        newItem.createdBy = req.user._id;

        console.log(newItem);
        const insertedItem = await items.insertOne(newItem);
        return insertedItem.insertedId;
    } catch (error) {
        console.log('error: ' + error);
        return "error"
    }
}

const getItem = async (id) => {
    //connect to collection
    await client.connect();
    const db = client.db('lists');
    const items = db.collection('items');

    const item = await items.findOne({ _id: ObjectId.createFromHexString(id.toString()) });

    return item;
}

const getUser = async (id) => {
    //connect to collection
    await client.connect();
    const db = client.db('users');
    const profiles = db.collection('profiles');

    const user = await profiles.findOne({ _id: ObjectId.createFromHexString(id.toString()) });
    if (user !== null && user !== undefined) {
        return user;
    } else {
        console.log("could not find user with id: " + id);
        return "error";
    }
}

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
            const users = db.collection('profiles');

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

// Route to decline friend request
app.post('/declineFriendRequest', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('users');
            const notifications = db.collection('notifications');

            //check if request exists
            const existingRequest = await notifications.findOne({ _id: ObjectId.createFromHexString(req.body.requestId.toString()) });

            if (existingRequest === null || existingRequest === undefined) {
                res.json({ message: "friend request doesn't exist" });
            } else if ( req.user._id.toString() !== existingRequest.receiver.toString() ) {
                res.json({ message: "user isn't the intended recipient" });
            } else {
                await notifications.deleteOne({ _id: existingRequest._id });
                res.json({ message: "success" });
            }

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to remove a friend
app.post('/removeFriend', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('users');
            const users = db.collection('profiles');

            if (req.user.friends.filter(x => x.toString() === req.body.user.toString()).length > 0) {
                let updatedFriendsList = req.user.friends.filter(x => x.toString() != req.body.user.toString());
                await users.updateOne({ _id: req.user._id }, { $set: { friends: updatedFriendsList } });

                const otherUser = await users.findOne({ _id: ObjectId.createFromHexString(req.body.user.toString()) });

                if (otherUser !== null && otherUser !== undefined) {
                    let otherUsersUpdatedFriendList = otherUser.friends.filter(x => x.toString() !== req.user._id.toString());
                    await users.updateOne({ _id: otherUser._id }, { $set: { friends: otherUsersUpdatedFriendList } });
                }
                res.json({ message: "success", updatedFriendsList: updatedFriendsList });

            } else {
                res.json({ message: "friend doesn't exist in friend user's friend list" });
            }

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to fidnd items
app.post('/findItems', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('lists');
            const items = db.collection('items');

            console.log('finding items');

            const existingItems = await items.find({ title: { $regex: req.body.title.trim().toLowerCase() } }).toArray();

            if (existingItems.length > 0) {
                console.log(existingItems);
                res.json({ message: "success", items: existingItems });
            }else {
                const getImage = await scrapeImages(req.body.title);
                let imageLink;
                if (getImage.items && getImage.items.length > 0) {
                    imageLink = getImage.items[0].link;
                }else {
                    imageLink = IMAGE_NOT_FOUND;
                }
                const newItem = {
                    title: req.body.title,
                    image: imageLink,
                }
                console.log(newItem);
                res.json({ message: "success", items: [newItem] });
            }

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});


// Route to create a list
app.post('/createList', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            if (req.body.listItems.length < 10) {
                console.log("list does not have 10 items");
                res.json({ message: "list does not have 10 items" });
                return;
            } else {
                //connect to collection
                await client.connect();
                const db = client.db('lists');
                const lists = db.collection('lists');

                let newItemsList = [];

                for (let i = 0; i < req.body.listItems.length; i++) {
                    const id = req.body.listItems[i]._id;
                    if (id === null || id === undefined) {
                        const newItemId = await addItemToDb(req.body.listItems[i], req);
                        if (newItemId !== "error") {
                            newItemsList.push(ObjectId.createFromHexString(newItemId.toString()));
                        }else {
                            break;
                        }
                    }else {
                        newItemsList.push(ObjectId.createFromHexString(id.toString()));
                    }
                }

                if (newItemsList.length !== 10) {
                    console.log("something went wrong adding one of the items from the list");
                    res.json({ message: "could not create list, something went wrong adding one of the items from the list to the database." });
                    return;
                }else {
                    const r = Math.floor(Math.random() * 156) + 100; // 100-255 for softer colors
                    const g = Math.floor(Math.random() * 156) + 100;
                    const b = Math.floor(Math.random() * 156) + 100;
                    const a = (Math.random() * 0.5 + 0.5).toFixed(2);
                    let newList = {
                        userId: req.user._id,
                        createdTimestamp: new Date(),
                        title: req.body.title.toLowerCase().trim(),
                        items: newItemsList,
                        backgroundColor: `rgba(${r}, ${g}, ${b}, ${a})`
                    }

                    const newlyInsertedList = await lists.insertOne(newList);

                    newList._id = newlyInsertedList.insertedId;
                    res.json({ message: "success", list: newList });
                    return;
                }
            }
        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to search a list
app.post('/searchList', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('lists');
            const lists = db.collection("lists");

            const returnedLists = lists.find({ title: { $regex: req.body.query } }).toArray();

            res.json({ message: "success", lists: returnedLists });
        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to return lists with pagination
app.post('/getLists', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            // Connect to collection
            await client.connect();
            const db = client.db('lists');
            const lists = db.collection("lists");

            // Extract pagination parameters
            const { page = 1, limit = 10 } = req.body;
            const skip = (page - 1) * limit;

            // Fetch data with pagination
            const returnedLists = await lists.aggregate([
                { $skip: skip },
                { $limit: limit }
            ]).toArray();

            let newLists = [];

            for (let i = 0; i < returnedLists.length; i++) {
                let newList = returnedLists[i];
                let newItemsList = [];
                for (let j = 0; j < newList.items.length; j++) {
                    const item = await getItem(newList.items[j]);
                    if (item._id !== null && item._id !== undefined) {
                        newItemsList.push(item);
                    } else {
                        console.log("could not get item with id: " + newList.items[j])
                        break;
                    }
                }
                if (newItemsList.length !== 10) {
                    console.log("could lot get items for list with Id: " + newList._id);
                    break;
                }else {
                    const user = await getUser(newList.userId);
                    if (user !== "error") {
                        newList.items = newItemsList;
                        newList.user = user;
                        newLists.push(newList);
                    }else {
                        console.log("could not get user");
                        break;
                    }
                }
            }

            if (newLists.length !== returnedLists.length) {
                console.log("could not retrieve items for lists");
                res.json({ message: "could not retrieve items for lists" });
                return;
            }else {
                res.json({ message: "success", lists: newLists });
            }            
        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    } catch (error) {
        console.log(error);
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
        const data = await scrapeImages(query);

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

const FRONTEND_PATH = path.join(__dirname, `${process.env.FRONTEND_FILE_PATH}`);

console.log('Serving frontend from:', FRONTEND_PATH);
console.log(`path: http://127.0.0.1:${process.env.PORT}`);

app.get('/', (req, res) => {
    console.log('working');
    if (req.isAuthenticated()) {
        res.redirect('/feed');
    } else {
        res.sendFile(path.join(FRONTEND_PATH, 'index.html'));
    }
    
});

app.use(express.static(FRONTEND_PATH))

app.get('/*', (req, res) => {
    console.log(`Serving SPA route for: ${req.originalUrl}`);
    const routes = ['/','/friends','/feed','/createlist','/settings'];
    if (routes.includes(req.originalUrl) && req.isAuthenticated()) {
        res.sendFile(path.join(FRONTEND_PATH, 'index.html'));
    } else if (!routes.includes(req.originalUrl)){
        res.sendFile(path.join(FRONTEND_PATH, `${decodeURIComponent(req.originalUrl)}`));
    }else {
        res.redirect('/');
    }
});




app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});
