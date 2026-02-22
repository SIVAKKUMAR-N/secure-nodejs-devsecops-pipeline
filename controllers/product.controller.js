const product = require('../models/product.model.js');

const getproducts = async (req, res) => {
    try {
        const newproducts = await product.find({});
        res.status(200).json(newproducts);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
const getproduct = async (req, res) => {
    try {
        const { id } = req.params;
        const singleproduct = await product.findById(id);
        if (!singleproduct) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.status(200).json(singleproduct);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

const postproduct = async (req, res) => {
    try {
        const newproduct = await product.create(req.body);
        res.status(201).json(newproduct);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

const updateproduct = async (req, res) => {
    try {
        const { id } = req.params;
        const item = await product.findByIdAndUpdate(id, req.body);
        if (!item) {
            return res.status(404).json({ message: 'Product not found' });
        }
        const updatedproduct = await product.findById(id);
        res.status(200).json(updatedproduct);
    }
    catch (error) {
        res.status(500).json({ message: error.message });
    }
};

const deleteproduct = async (req, res) => {
    try {
        const { id } = req.params;
        const items = await product.findByIdAndDelete(id);
        res.status(200).json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

module.exports = {
    getproducts,
    getproduct,
    postproduct,
    updateproduct,
    deleteproduct
};
