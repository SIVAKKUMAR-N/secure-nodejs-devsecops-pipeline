const mongoose = require('mongoose');

// ✅ Define the Product schema
const productSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please enter product name'],
    },
    quantity: {
      type: Number,
      required: true,
      default: 0,
    },
    price: {
      type: Number,
      required: true,
      default: 0,
    },
    image: {
      type: String,  // ✅ Use capital 'S' in String
      required: false,
    },
  },
  {
    // ✅ timestamps: true automatically adds:
    // - createdAt → when document is created
    // - updatedAt → when document is updated
    // 💡 Helpful for logs, sorting, filtering, tracking changes
    timestamps: true
  }
);
const product = mongoose.model('Product', productSchema);
module.exports = product; // ✅ Export the model
// ✅ Use 'product' as the model name, it will create 'products' collection in MongoDB
// ✅ Mongoose automatically pluralizes the model name to create the collection name