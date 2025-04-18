const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");

const shopSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please enter your shop name"],
    trim: true,
  },
  email: {
    type: String,
    required: [true, "Please provide your email"],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, "Please provide a valid email"],
  },
  password: {
    type: String,
    required: [true, "Please enter your password"],
    minLength: [6, "Password should be greater than 6 characters"],
    select: false,
  },
  description: {
    type: String,
    trim: true,
  },
  address: {
    type: String,
    required: true,
  },
  phoneNumber: {
    countryCode: {
      type: String,
      match: [/^\+\d{1,3}$/, "Invalid country code (e.g., +1, +44)"],
    },
    number: {
      type: String,
      match: [/^\d{7,15}$/, "Phone number must be 7-15 digits"],
    },
  },
  role: {
    type: String,
    default: "Seller",
  },
  avatar: {
    public_id: { type: String, required: false },
    url: { type: String, required: true },
  },
  approvalStatus: {
    isSellerApproved: { type: Boolean, default: false },
  },
  zipCode: {
    type: String,
    required: true,
  },
  withdrawMethod: {
    type: Object,
  },
  availableBalance: {
    type: Number,
    default: 0,
  },
  transactions: [
    {
      amount: { type: Number, required: true },
      status: { type: String, default: "Processing" },
      createdAt: { type: Date, default: Date.now },
      updatedAt: { type: Date },
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now,
  },
  verificationOtp: String,
  verificationOtpExpiry: Number,
  isVerified: { type: Boolean, default: false },
  resetPasswordToken: String,
  resetPasswordTime: Date,
});

// Hash password
shopSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }
  this.password = await bcrypt.hash(this.password, 10);
});

// JWT token
shopSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_EXPIRES,
  });
};

// Compare password
shopSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Password reset token
shopSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.resetPasswordTime = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

module.exports = mongoose.model("Shop", shopSchema);
