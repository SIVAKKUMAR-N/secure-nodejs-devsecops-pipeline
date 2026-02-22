const express = require('express');
const product = require('../models/product.model.js');
const router = express.Router();
const { getproducts, getproduct, postproduct, updateproduct, deleteproduct } = require('../controllers/product.controller.js');



//get all the products details
router.get('/', getproducts);

//get product details using id
router.get('/:id', getproduct);

//create or post a product
router.post('/', postproduct);

// change or update the specific product details using id
router.put('/:id', updateproduct);

//deleting the specific product using id
router.delete('/:id', deleteproduct);

module.exports = router;


