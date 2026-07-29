require("dotenv").config();

const express = require("express");
const productRoutes = require("./routes/product.route.js");

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Routes
app.use("/api/products", productRoutes);

app.get("/", (req, res) => {
    res.send("response from server");
});

module.exports = app;