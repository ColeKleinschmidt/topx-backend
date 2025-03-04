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

        if (!isValidEmail(email)) {
            return done(null, false, {message: "invalid email"});
        }

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

function capitalizeWords(str) {
    return str.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
}

function isValidEmail(email) {
    if (typeof email !== 'string') {
      return false;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

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

const getUser = async (idBool, id) => {
    //connect to collection
    await client.connect();
    const db = client.db('users');
    const profiles = db.collection('profiles');

    let user;
    if (idBool) {
        user = await profiles.findOne({ _id: ObjectId.createFromHexString(id.toString()) });
    } else {
        user = await profiles.findOne({ username: id });
    }

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

    if (!isValidEmail(email)) {
        return res.status(400).json({ message: "invalid email" });
    }

    if (username.includes('-')) {
        return res.status(400).json({ message: "username cannot contain a '-'" });
    }

    try {
        await client.connect();
        const db = client.db('users');
        const users = db.collection('profiles');

        const existingUser = await users.findOne({ $or: [{ email: email}, {username: username }] });
        if (existingUser) {
            const emailExists = existingUser.email == email ? true : false;
            console.log(emailExists ? "user with email " + email + " already exists" : "user with username " + username + " already exists");
            return res.status(400).json({ message: emailExists ? 'Email already in use' : 'Username already in use'});
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { 
            email, 
            password: hashedPassword, 
            username,
            createdTimestamp: new Date(),
            lastLoginTimestamp: new Date(),
            friends: [],
            ignoredUsers: [],
            blockedUsers: [],
            profilePicture: "https://static.vecteezy.com/system/resources/previews/036/280/650/non_2x/default-avatar-profile-icon-social-media-user-image-gray-avatar-icon-blank-profile-silhouette-illustration-vector.jpg"
        };
        console.log("inserting new user into database: ");
        console.log(newUser);

        const result = await users.insertOne(newUser);
        newUser._id = result.insertedId;

        // Manually log the user in
        req.login(newUser, (err) => {
            if (err) {
                return next(err);
            }
            res.status(201).json({ 
                message: 'Account created successfully', 
                user: { _id: newUser._id, email, username, profilePicture: newUser.profilePicture } 
            });
        });
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

// Route to get users minus the current user
app.get('/getUsers', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            await client.connect();
            const db = client.db('users');
            const users = db.collection('profiles');
            let allUsers = await users.find().toArray();
            allUsers = allUsers.filter(x => x._id.toString() !== req.user._id.toString() && req.user.friends.filter(y => y.toString() == x._id.toString() ).length === 0);
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
            const existingRequest = await notifications.find({type: 'friendRequest', $or: [ { sender: req.user._id, receiver: ObjectId.createFromHexString(req.body.receiver.toString()) }, { sender: ObjectId.createFromHexString(req.body.receiver.toString()), receiver: req.user._id } ] }).toArray();

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

app.get('/getPendingFriendRequests', async (req, res) => 
    {
        try 
        {
            if (!req.isAuthenticated()) 
            {
                return res.status(401).json({ message: "Unauthorized" });
            }
    
            await client.connect();
            const db = client.db('users'); // Change if needed
            const notifications = db.collection('notifications'); // Collection storing friend requests
    
            // ✅ Find friend requests where the logged-in user is the sender & type is "friendRequest"
            const pendingRequests = await notifications.find({ 
                sender: req.user._id, 
                type: "friendRequest" 
            }).toArray();
    
            // ✅ Extract only the receiver IDs (who the request was sent to)
            const pendingUserIds = pendingRequests.map(req => req.receiver.toString());
    
            res.json({ requests: pendingUserIds });
        } 
        catch (error) 
        {
            console.error("❌ Error fetching pending requests:", error);
            res.status(500).json({ message: "Server error", error });
        }
    });    
    
// Route to get all user notifications
app.get('/getAllNotifications', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('users');
            const notifications = db.collection('notifications');

            const getAllNotifications = await notifications.find({ $or: [{ receiver: ObjectId.createFromHexString(req.user._id.toString()) }, { sender: ObjectId.createFromHexString(req.user._id.toString()) }] }).toArray();

            res.send({ message: "success", notifications: getAllNotifications });

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to get all user's friends
app.get('/getFriends', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('users');
            const profiles = db.collection('profiles');

            let allFriends = [];
            for (let i = 0; i < req.user.friends.length; i++) {
                const friend = await profiles.findOne({ _id: ObjectId.createFromHexString(req.user.friends[i].toString()) });
                console.log(friend);
                if (friend !== null && friend !== undefined) {
                    console.log('pushing now');
                    const newFriend = {
                        _id: friend._id,
                        username: friend.username,
                        profilePicture: friend.profilePicture
                    }
                    allFriends.push(newFriend);
                }
            }
            res.status(200).json({ message: "success", friends: allFriends });

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
    console.log('declining request with id: ' + req.body.requestId);
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

            const existingItems = await items.find({ title: { $regex: capitalizeWords(req.body.title.trim().toLowerCase()) } }).toArray();

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
                    title: capitalizeWords(req.body.title.trim().toLowerCase()),
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

// Route to fidnd items
app.get('/removeAllItems', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            //connect to collection
            await client.connect();
            const db = client.db('lists');
            const items = db.collection('items');

            console.log('finding items');

            await items.deleteMany();

            res.status(200).json({ message: "all items are deleted" });

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
                const listDb = client.db('lists');
                const lists = listDb.collection('lists');
                const items = listDb.collection("items");

                let newItemsList = [];

                for (let i = 0; i < req.body.listItems.length; i++) {
                    const existingItem = await items.findOne({ title: capitalizeWords(req.body.listItems[i].title.trim().toLowerCase()) });
                    if (existingItem == null || existingItem == undefined) {
                        const newItemId = await addItemToDb(req.body.listItems[i], req);
                        if (newItemId !== "error") {
                            let item = req.body.listItems[i];
                            item._id = ObjectId.createFromHexString(newItemId.toString());
                            newItemsList.push(item);
                        }else {
                            break;
                        }
                    }else {
                        newItemsList.push(req.body.listItems[i]);
                    }
                }

                if (newItemsList.length !== 10) {
                    console.log("something went wrong adding one of the items from the list");
                    res.json({ message: "could not create list, something went wrong adding one of the items from the list to the database." });
                    return;
                }else {
                    const r = Math.floor(Math.random() * 70) + 30; // 30-100 for darker tones
                    const g = Math.floor(Math.random() * 70) + 30;
                    const b = Math.floor(Math.random() * 70) + 30;
                    let newList = {
                        user: {
                            _id: req.user._id,
                            username: req.user.username,
                            profilePicture: req.user.profilePicture
                        },
                        createdTimestamp: new Date(),
                        title: capitalizeWords(req.body.title.toLowerCase().trim()),
                        items: newItemsList,
                        backgroundColor: `rgba(${r}, ${g}, ${b}, 1)`
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

// Route to return lists with pagination (EXCLUDES BLOCKED USERS' LISTS)
app.post('/getLists', async (req, res) => 
{
    try 
    {
        if (!req.isAuthenticated()) 
        {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        await client.connect();
        const db = client.db('lists');
        const lists = db.collection("lists");
        const profiles = client.db("users").collection("profiles"); // User profiles collection

        const { page = 1, limit = 10 } = req.body;
        const skip = (page - 1) * limit;

        // ✅ Fetch blocked users list for the logged-in user
        const currentUser = await profiles.findOne({ _id: req.user._id });

        if (!currentUser) 
        {
            return res.status(404).json({ message: "User not found." });
        }

        const blockedUserIds = currentUser.blockedUsers || []; // Get list of blocked user IDs

        // ✅ Exclude lists from blocked users
        let returnedLists = await lists.aggregate([
            { $match: { userId: { $nin: blockedUserIds } } }, // Exclude blocked users
            { $sort: { createdTimestamp: -1 } },
            { $skip: skip },
            { $limit: limit }
        ]).toArray();

        res.status(200).json({ message: "success", lists: returnedLists });
    } 
    catch (error) 
    {
        console.log("🚨 Error fetching lists:", error);
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to return a specified list by ID
app.post('/getList', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            // Connect to collection
            await client.connect();
            const db = client.db('lists');
            const lists = db.collection("lists");

            const list = await lists.findOne({ _id: ObjectId.createFromHexString(req.body.listId.toString()) });

            if (list !== null && list !== undefined) {
                res.status(200).json({ message: "success", list: list });
            }else {
                res.status(400).json({ message: "could not find list" });
            }

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to share a list
app.post('/shareList', async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            // Connect to collection
            await client.connect();
            const db = client.db('users');
            const notifications = db.collection("notifications");

            let newNotification = {
                sender: ObjectId.createFromHexString(req.user._id.toString()),
                receiver: ObjectId.createFromHexString(req.body.userId.toString()),
                createdTimestamp: new Date(),
                type: "share",
                listId: ObjectId.createFromHexString(req.body.listId.toString())
            }

            const returnedNotification = await notifications.insertOne(newNotification);

            newNotification._id = returnedNotification.insertedId;

            res.status(200).json({ message: "success", newNotification: newNotification });

        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Server error', error });
    }
});

// Route to get user with given username
app.post('/getUserByUsername', async (req, res) => {
    try {
        const user = await getUser(false, req.body.username);
        if (user === "error") {
            console.log("NO USER FOUND");
            return res.json({ message: "no user found" });
        }else {
            console.log("USER FOUND");
            return res.json({ message: "success", user: user });
        }
    } catch (error) {
        return res.status(400).json({ message: error.toString() });
    }

});

// Route to get user with given id
app.post('/getUserById', async (req, res) => {
    try {
        const user = await getUser(true, req.body.id);
        if (user === "error") {
            console.log("NO USER FOUND");
            return res.json({ message: "no user found" });
        }else {
            console.log("USER FOUND");
            return res.json({ message: "success", user: user });
        }
    } catch (error) {
        return res.status(400).json({ message: error.toString() });
    }

});

app.post('/getListsByUserId', async (req, res) => 
{
    try 
    {
        if (req.isAuthenticated()) 
        {
            await client.connect();
            const db = client.db('lists');
            const listsCollection = db.collection("lists");

            console.log("Received request with body:", req.body);

            let { userId, page = 1, limit = 10 } = req.body;
            if (!userId) 
            {
                return res.status(400).json({ message: "Missing userId" });
            }

            const skip = (page - 1) * limit;

            // Convert userId to ObjectId
            let query = { "user._id": new ObjectId(userId) };

            console.log(`Searching for lists with query:`, query);

            const userLists = await listsCollection
                .find(query, 
                {
                    projection: 
                    {
                        _id: 1, 
                        "user._id": 1, 
                        "user.username": 1, 
                        "user.profilePicture": 1,
                        title: 1,
                        createdTimestamp: 1,
                        backgroundColor: 1,
                        "items.title": 1,
                        "items.image": 1
                    }
                }) 
                .sort({ createdTimestamp: -1 })
                .skip(skip)
                .limit(limit)
                .toArray();

            console.log(`Found ${userLists.length} lists for userId ${userId}`);

            res.status(200).json({ message: "success", lists: userLists });
        } 
        else 
        {
            res.status(401).json({ message: 'Unauthorized' });
        }
    } 
    catch (error) 
    {
        console.log("Server error:", error);
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

app.post('/ignoreUser', async (req, res) => 
{
    console.log(`Ignoring user request received for: ${req.originalUrl}`);

    const { userId, ignoredUserId } = req.body;

    if (!userId || !ignoredUserId) 
    {
        return res.status(400).json({ message: "Both userId and ignoredUserId are required." });
    }

    try 
    {
        await client.connect();
        const db = client.db('users');
        const users = db.collection('profiles');

        console.log(`Adding ignored user: ${ignoredUserId} to user: ${userId}`);

        await users.updateOne(
            { _id: new ObjectId(userId) }, 
            { $addToSet: { ignoredUsers: new ObjectId(ignoredUserId) } } // Prevents duplicates
        );

        console.log(`User ${ignoredUserId} ignored successfully.`);
        res.json({ message: "User ignored successfully." });

    } 
    catch (error) 
    {
        console.error("Error ignoring user:", error);
        res.status(500).json({ message: "Server error" });
    }
});

app.get('/getIgnoredUsers', async (req, res) => 
{
    try 
    {
        if (!req.isAuthenticated()) 
        {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        await client.connect();
        const db = client.db("users");
        const profiles = db.collection("profiles");

        const currentUser = await profiles.findOne({ _id: req.user._id });

        if (!currentUser) 
        {
            return res.status(404).json({ message: "User not found." });
        }

        console.log("🚫 Ignored Users List:", currentUser.ignoredUsers);

        res.status(200).json({ ignoredUsers: currentUser.ignoredUsers || [] });
    } 
    catch (error) 
    {
        console.log("🚨 Server error:", error);
        res.status(500).json({ message: 'Server error', error });
    }
});

app.post('/toggleBlockUser', async (req, res) => 
{
    try 
    {
        if (!req.isAuthenticated()) 
        {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        await client.connect();
        const db = client.db("users");
        const profiles = db.collection("profiles");

        const { userId, blockedUserId } = req.body;

        if (!userId || !blockedUserId) 
        {
            return res.status(400).json({ message: "Missing user ID or blocked user ID." });
        }

        const currentUser = await profiles.findOne({ _id: new ObjectId(userId) });

        if (!currentUser) 
        {
            return res.status(404).json({ message: "User not found." });
        }

        const isBlocked = currentUser.blockedUsers?.includes(blockedUserId);

        if (isBlocked) 
        {
            // ✅ Unblock user and remove from ignoredUsers
            await profiles.updateOne(
                { _id: new ObjectId(userId) },
                { 
                    $pull: { blockedUsers: blockedUserId, ignoredUsers: blockedUserId }
                }
            );

            console.log(`✅ User ${blockedUserId} unblocked by ${userId}`);
            return res.status(200).json({ message: "unblocked" });
        } 
        else 
        {
            // ✅ Block user and add to ignoredUsers
            await profiles.updateOne(
                { _id: new ObjectId(userId) },
                { 
                    $addToSet: { blockedUsers: blockedUserId, ignoredUsers: blockedUserId }
                }
            );

            console.log(`🚫 User ${blockedUserId} blocked by ${userId}`);
            return res.status(200).json({ message: "blocked" });
        }
    } 
    catch (error) 
    {
        console.error("🚨 Server error:", error);
        res.status(500).json({ message: "Server error", error });
    }
});

// ✅ Ensure this is at the top of your route definitions
app.get('/getBlockedUsers', async (req, res) => 
{
    try 
    {
        if (!req.isAuthenticated()) 
        {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        await client.connect();
        const db = client.db("users");
        const profiles = db.collection("profiles");

        const currentUser = await profiles.findOne({ _id: req.user._id });

        if (!currentUser) 
        {
            return res.status(404).json({ message: "User not found." });
        }

        res.status(200).json({ blockedUsers: currentUser.blockedUsers || [] });
    } 
    catch (error) 
    {
        console.log("🚨 Error fetching blocked users:", error);
        res.status(500).json({ message: 'Server error', error });
    }
});

app.post('/getLists', async (req, res) => 
{
    try 
    {
        if (!req.isAuthenticated()) 
        {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        await client.connect();
        const db = client.db('lists');
        const lists = db.collection("lists");
        const profiles = client.db("users").collection("profiles");

        const { page = 1, limit = 10 } = req.body;
        const skip = (page - 1) * limit;

        // ✅ Fetch blocked users list for the logged-in user
        const currentUser = await profiles.findOne({ _id: new ObjectId(req.user._id) });

        if (!currentUser) 
        {
            console.log("❌ User not found in profiles collection.");
            return res.status(404).json({ message: "User not found." });
        }

        let blockedUserIds = currentUser.blockedUsers || [];

        // ✅ Ensure blockedUserIds are converted correctly
        if (blockedUserIds.length > 0) 
        {
            try 
            {
                blockedUserIds = blockedUserIds.map(id => new ObjectId(id));
            } 
            catch (error) 
            {
                console.error("🚨 Error converting blockedUserIds to ObjectId:", error);
            }
        }

        console.log("🚫 Blocked User IDs (converted):", blockedUserIds); // ✅ Debugging

        // ✅ Ensure correct filtering before querying MongoDB
        const queryFilter = { userId: { $nin: blockedUserIds } };
        console.log("🔍 Querying lists with filter:", JSON.stringify(queryFilter));

        // ✅ Fetch lists while excluding blocked users
        let returnedLists = await lists.aggregate([
            { $match: queryFilter }, // ✅ Ensure blocked users are excluded
            { $sort: { createdTimestamp: -1 } },
            { $skip: skip },
            { $limit: limit },
            {
                $project: 
                {
                    userId: { $ifNull: ["$userId", "UNKNOWN"] }, // ✅ Ensure userId is always included
                    title: 1,
                    items: 1,
                    createdTimestamp: 1
                }
            }
        ]).toArray();

        console.log("✅ Filtered Lists Sent:", JSON.stringify(returnedLists, null, 2)); // ✅ Debugging

        res.status(200).json({ message: "success", lists: returnedLists });
    } 
    catch (error) 
    {
        console.log("🚨 Error fetching lists:", error);
        res.status(500).json({ message: 'Server error', error });
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

app.get('/*', (req, res, next) => {

    if (req.originalUrl.startsWith('/getIgnoredUsers') || req.originalUrl.startsWith('/api/')) 
    {
            return next();
    }
    console.log(`Serving SPA route for: ${req.originalUrl}`);
    const routes = ['/','/friends','/feed','/createlist','/settings'];
    if (
        (routes.includes(req.originalUrl) || /^\/user\/[a-zA-Z0-9]+$/.test(req.originalUrl) || /^\/list\/[a-zA-Z0-9]+$/.test(req.originalUrl)) &&  
        req.isAuthenticated()
    ) {
        console.log('sending correct file');
        res.sendFile(path.join(FRONTEND_PATH, 'index.html'));
    } else if (!routes.includes(req.originalUrl)) {
        res.sendFile(path.join(FRONTEND_PATH, `${decodeURIComponent(req.originalUrl)}`));
    } else {
        res.redirect('/');
    }
});
    
app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});
