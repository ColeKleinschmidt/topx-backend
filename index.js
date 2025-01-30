// Import dependencies
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
require('dotenv').config();

// Initialize express app
const app = express();

// Use middlewares
app.use(cors());
app.use(bodyParser.json());
//app.use(passport.initialize());
//app.use(passport.session());

// Connection URI
const uri = `mongodb+srv://topxAdmin:${process.env.MONGO_PASSWORD}@topx.c8dwz.mongodb.net/?retryWrites=true&w=majority&appName=TopX`;

//Create a MongoClient
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
            return done(null, false, { message: 'User not found' });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Incorrect password' });
        }
        
        return done(null, user);
    } catch (error) {
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
        const db = client.db('TopX');
        const users = db.collection('users');
        const user = await users.findOne({ _id: new ObjectId(id) });
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Route to create an account
app.post('/createAccount', async (req, res) => {
    const { email, password, username } = req.body;
    
    if (!email || !password || !username) {
        return res.status(400).json({ message: 'All fields are required' });
    }
    
    try {
        await client.connect();
        const db = client.db('users');
        const users = db.collection('profiles');
        
        const existingUser = await users.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { email, password: hashedPassword, username };
        
        const result = await users.insertOne(newUser);
        res.status(201).json({ message: 'Account created successfully', userId: result.insertedId });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

app.get("/", async (req, res) => {
    res.send({ serverStatus: "running" });
})

app.listen(8080, () => {
    console.log("server is running");
 });

// app.post('/testPostCall', async (req, res) => {
//     const name = req.body.name;
//     console.log(name);
//     res.send({ message: `Hello ${name}` });
// });

// app.get('/', async (req, res) => {
//     res.send({ serverStatus: "running" });
// });