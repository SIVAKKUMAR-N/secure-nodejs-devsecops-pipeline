require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const product = require('./models/product.model.js'); // Import the product model
const app = express()

//middleware
app.use(express.json()); // Middleware to parse JSON bodies
app.use(express.urlencoded({ extended: false })); // Middleware to parse URL-encoded bodies
const productRoutes = require('./routes/product.route.js');
const PORT = 3000;

//routes
app.use('/api/products', productRoutes);


//database connection
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB')
        //checking if the server runs on 3000 or not
        app.listen(PORT, () => {
            console.log('Server is running on port 3000');
        });
    })
    .catch(() => {
        console.log('Error connecting to MongoDB');
    });


//check if the server gives response or not
app.get('/', (req, res) => {
    res.send('respone from server');
});

