const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const uri = `<fill with connection URL>`;

//Create a MongoClient
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

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