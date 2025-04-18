const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema({
  cart: [
    {
      _id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true,
      },
      name: { type: String, required: true },
      price: { type: Number, required: true },
      quantity: { type: Number, required: true, min: 1 },
      image: { public_id: String, url: String },
      isReviewed: { type: Boolean, default: false },
    },
  ],
  shippingAddress: {
    address: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String },
    country: { type: String, required: true },
    zipCode: { type: String, required: true },
  },
  user: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
  },
  totalPrice: {
    type: Number,
    required: true,
    min: 0,
  },
  status: {
    type: String,
    enum: ["Processing", "Shipped", "Delivered", "Cancelled"],
    default: "Processing",
  },
  paymentInfo: {
    id: { type: String },
    status: { type: String },
    type: { type: String },
  },
  paidAt: {
    type: Date,
    default: Date.now,
  },
  deliveredAt: {
    type: Date,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Populate product in cart
orderSchema.pre(/^find/, function (next) {
  this.populate("cart._id", "name price images");
  next();
});

module.exports = mongoose.model("Order", orderSchema);
